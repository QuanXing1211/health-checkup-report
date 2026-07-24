"""
通用 HTML → Word 转换
=====================
将 standalone HTML 报告（含 ECharts / iframe 动态内容）转换为 .docx 文档。

采用「混合保真」策略：
  - 标题 / 段落 / 表格 / 普通图片 → 结构化映射到 Word 原生元素（可编辑）
  - ECharts 图表 / iframe sketch 图 / JS 动态 SVG → 截图嵌入（保视觉）

用法:
    # 默认转换（A4 横版分页）
    python -m html_to_word.html_to_word_export --input "security-report-preview-2.0-standalone(3).html"

    # 指定输出路径
    python -m html_to_word.html_to_word_export --input xxx.html --output xxx.docx

    # 指定预览模式（默认 a4-landscape）
    python -m html_to_word.html_to_word_export --input xxx.html --preview-mode a4-portrait

    # 自定义配置文件
    python -m html_to_word.html_to_word_export --input xxx.html --config html_to_word/html_to_word_config.yaml
"""

import argparse
import base64
import io
import os
import re
from pathlib import Path

import yaml
from bs4 import BeautifulSoup, Comment, NavigableString, Tag
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor, Emu
from PIL import Image

# 默认配置（与 html_to_word_config.yaml 同步，配置缺失时回退到此）
_DEFAULT_CONFIG = {
    "preview_mode": "html",
    "trigger_paginate": False,
    "render_wait": {"after_load_ms": 2000, "ready_markers": []},
    "dom_root": "#sr-page-source",
    "skip_selectors": [".sr-nav-wrap", ".sr-toc-page", ".sr-copyright-page", ".sr-dev-reference", ".sr-hidden-charts"],
    "snapshot_selectors": [
        ".sr-chart-slot",
        ".sr-chart-card",
        ".sr-chart-live",
        ".sr-asset-donut-row",
        "iframe",
        ".sr-chart-empty",
    ],
    "style_map": {
        "h1": "heading_1", "h2": "heading_2", "h3": "heading_3",
        "h4": "heading_4", "h5": "heading_5", "h6": "heading_6",
        "p": "paragraph", "table": "table",
        "ul": "bullet_list", "ol": "number_list", "img": "image",
        ".sr-risk-card": "risk_card_table",
        ".sr-risk-card__head": "risk_card_head",
        ".sr-kpi-card": "kpi_paragraph",
        ".sr-top5-asset-ip-row": "top5_asset_ip_row",
        ".sr-tag--critical": "tag_critical",
        ".sr-tag--high": "tag_high",
        ".sr-tag--medium": "tag_medium",
        ".sr-tag--medium-low": "tag_medium_low",
        ".sr-tag--low": "tag_low",
        ".sr-tag--info": "tag_info",
        ".sr-tag--success": "tag_success",
        ".sr-tag--blue": "tag_blue",
        ".sr-tag--light": "tag_light",
        ".sr-grade": "grade_badge",
        ".report-chart-note": "muted_note",
        ".sr-p--sub": "sub_paragraph",
    },
    "docx": {"page_width_mm": 210, "page_height_mm": 297, "margin_mm": 20},
    "fonts": {
        "normal": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                   "size_pt": 10.5, "color_hex": "000000"},
        "heading_1": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 22, "bold": True, "color_hex": "1F4E79",
                      "space_before_pt": 12, "space_after_pt": 6},
        "heading_2": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 18, "bold": True, "color_hex": "1F4E79",
                      "space_before_pt": 10, "space_after_pt": 6},
        "heading_3": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 16, "bold": True, "color_hex": "2E5C8A",
                      "space_before_pt": 8, "space_after_pt": 4},
        "heading_4": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 14, "bold": True, "color_hex": "2E5C8A",
                      "space_before_pt": 6, "space_after_pt": 4},
        "heading_5": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 12, "bold": True, "color_hex": "44546A",
                      "space_before_pt": 6, "space_after_pt": 2},
        "heading_6": {"font": "Microsoft YaHei", "east_asia": "Microsoft YaHei",
                      "size_pt": 11, "bold": True, "color_hex": "44546A",
                      "space_before_pt": 4, "space_after_pt": 2},
    },
    "screenshot": {"type": "png", "scale": 2},
    "tmp_dir": "tmp/html_to_word",
    "update_fields_after_save": {
        "enabled": True,
        "backend": "win32com",
        "timeout_sec": 60,
        "fail_silently": True,
    },
}

# 风险标签色阶（CSS 变量对应色，Word 中用近似 RGB）
_TAG_COLORS = {
    "tag_critical": ("82010E", "FFFFFF"),
    "tag_high":     ("CF171D", "FFFFFF"),
    "tag_medium":   ("FA721B", "FFFFFF"),
    "tag_medium_low": ("D6860D", "FFFFFF"),
    "tag_low":      ("6F7785", "FFFFFF"),
    "tag_info":     ("0BA7B5", "FFFFFF"),
    "tag_success":  ("12A679", "FFFFFF"),
    "tag_blue":     ("1C6EFF", "FFFFFF"),
}

# 评级徽章 sr-grade 颜色映射
# HTML 中 sr-grade--xxx 用 10% 透明底 + 深色字，Word w:shd 无透明度，用浅 solid 底近似
# (背景色, 字体颜色)
_GRADE_COLORS = {
    "sr-grade--优":  ("E5F5EE", "0F8E66"),   # 绿色徽章
    "sr-grade--良":  ("E6F0FF", "1C6EFF"),   # 蓝色徽章
    "sr-grade--中":  ("FEEAD8", "B5530C"),   # 橙色徽章
    "sr-grade--差":  ("FBE5E6", "82010E"),   # 红色徽章
    "sr-grade--na":  ("EDEEF1", "6F7785"),   # 灰色徽章
}
_GRADE_DEFAULT = ("EDEEF1", "6F7785")


def _log(msg, level="INFO"):
    print(f"[{level}] {msg}")


class _Container:
    """统一封装 Document / Cell 的添加接口。

    - Document：直接用 add_heading / add_paragraph / add_table / add_picture
    - _Cell：用 add_paragraph / add_table；图片与标题用变体实现
    """

    def __init__(self, doc, cell=None, fonts=None):
        self.doc = doc
        self.cell = cell  # 非 None 表示容器是 Cell
        # 字体样式配置（来自 HtmlToWordExporter.config["fonts"]），
        # 用于单元格内标题字号/颜色/东亚字体回退。
        self.fonts = fonts or {}

    @property
    def is_cell(self):
        return self.cell is not None

    def add_heading(self, text, level):
        if self.is_cell:
            p = self.cell.add_paragraph()
            run = p.add_run(text)
            run.bold = True
            # 优先读 fonts.heading_<level> 配置；缺省回退到内置字号映射
            heading_cfg = (self.fonts.get(f"heading_{level}", {}) or {}) if self.fonts else {}
            default_size_map = {1: 22, 2: 18, 3: 16, 4: 14, 5: 12, 6: 11}
            size_pt = heading_cfg.get("size_pt") or default_size_map.get(level, 11)
            run.font.size = Pt(size_pt)
            if heading_cfg.get("color_hex"):
                try:
                    run.font.color.rgb = RGBColor.from_string(heading_cfg["color_hex"])
                except (ValueError, AttributeError):
                    pass
            # 东亚字体：heading 优先，回退到 normal.east_asia
            ea = heading_cfg.get("east_asia") or (self.fonts.get("normal", {}) or {}).get("east_asia")
            latin = heading_cfg.get("font") or (self.fonts.get("normal", {}) or {}).get("font")
            if ea or latin:
                rPr = run._r.get_or_add_rPr()
                rFonts = rPr.find(qn("w:rFonts"))
                if rFonts is None:
                    rFonts = OxmlElement("w:rFonts")
                    rPr.append(rFonts)
                # 清除主题字体引用，避免 Word fallback 到主题字体（MS Gothic 等）
                for theme_attr in ("asciiTheme", "hAnsiTheme", "eastAsiaTheme", "cstheme"):
                    if rFonts.get(qn(f"w:{theme_attr}")) is not None:
                        del rFonts.attrib[qn(f"w:{theme_attr}")]
                if ea:
                    rFonts.set(qn("w:eastAsia"), ea)
                if latin:
                    rFonts.set(qn("w:ascii"), latin)
                    rFonts.set(qn("w:hAnsi"), latin)
            return p
        return self.doc.add_heading(text, level=level)

    def add_paragraph(self, text="", style=None):
        if self.is_cell:
            return self.cell.add_paragraph(text, style=style)
        return self.doc.add_paragraph(text, style=style)

    def add_table(self, rows, cols):
        if self.is_cell:
            return self.cell.add_table(rows, cols)
        return self.doc.add_table(rows, cols)

    def add_picture(self, image, width=None, height=None):
        if self.is_cell:
            # Cell 没有原生 add_picture：在新建段落里用 run.add_picture
            p = self.cell.add_paragraph()
            run = p.add_run()
            if isinstance(image, str):
                run.add_picture(image, width=width, height=height)
            else:
                run.add_picture(image, width=width, height=height)
            return p
        if isinstance(image, str):
            return self.doc.add_picture(image, width=width, height=height)
        return self.doc.add_picture(image, width=width, height=height)


def _css_to_bs4_selector(selector):
    """简单将 .cls / #id / tag 选择器转换为 bs4 find 参数。"""
    selector = selector.strip()
    if selector.startswith("#"):
        return {"id": selector[1:]}
    if selector.startswith("."):
        return {"class_": selector[1:].replace(".", " ")}
    return {"name": selector}


def _match_any(tag, selectors):
    """判断 tag 是否匹配任一选择器（仅支持 .cls / #id / tag 简单形式）。"""
    if not isinstance(tag, Tag):
        return False
    for sel in selectors:
        sel = sel.strip()
        if sel.startswith("#"):
            if tag.get("id") == sel[1:]:
                return True
        elif sel.startswith("."):
            classes = (tag.get("class") or [])
            needed = sel[1:].split(".")
            if all(c in classes for c in needed):
                return True
        else:
            if tag.name == sel:
                return True
    return False


class HtmlToWordExporter:
    """HTML → Word 转换器：渲染、截图、结构化映射、拼装 docx。"""

    def __init__(self, input_path, output_path=None, config_path=None, preview_mode=None):
        self.input_path = Path(input_path).resolve()
        if not self.input_path.exists():
            raise FileNotFoundError(f"输入 HTML 不存在: {self.input_path}")
        self.output_path = Path(output_path) if output_path else (
            Path("tmp") / (self.input_path.stem + ".docx")
        )
        # 默认使用脚本同目录下的 html_to_word_config.yaml，避免 main() 不传 --config 时
        # 直接落到内置 _DEFAULT_CONFIG，导致 yaml 中的 ready_markers 等修正不生效。
        default_cfg = Path(__file__).resolve().parent / "html_to_word_config.yaml"
        self.config_path = Path(config_path) if config_path else (
            default_cfg if default_cfg.exists() else None
        )
        self.config = dict(_DEFAULT_CONFIG)
        self._snapshot_index = 0
        self._snapshot_map = {}  # DOM 占位 id → 图片绝对路径
        # 延迟导入 playwright，避免无浏览器环境也能跑测试
        self._playwright_ctx = None
        self._page = None
        # 封面节点缓存（.sr-cover 在 dom_root 之外，extract_dom 时填充）
        self._cover_node = None
        # preview_mode 覆盖
        if preview_mode:
            self.config["preview_mode"] = preview_mode

    # ──────────────────────────────────────────────
    # 配置加载
    # ──────────────────────────────────────────────

    def load_config(self):
        """加载 YAML 配置，与默认配置深合并。"""
        if not self.config_path or not self.config_path.exists():
            _log(f"未指定配置文件，使用内置默认配置")
            return self.config
        with open(self.config_path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        # 深合并：用户配置覆盖默认配置
        for k, v in user_cfg.items():
            if isinstance(v, dict) and isinstance(self.config.get(k), dict):
                self.config[k] = {**self.config[k], **v}
            else:
                self.config[k] = v
        _log(f"已加载配置: {self.config_path}")
        return self.config

    # ──────────────────────────────────────────────
    # 渲染（Playwright）
    # ──────────────────────────────────────────────

    def render_html(self):
        """Playwright 启动 Chromium，加载 HTML，设置 preview-mode，等待渲染完成。返回 page。"""
        from playwright.sync_api import sync_playwright
        _log(f"启动 Chromium 渲染: {self.input_path.name}")
        self._playwright_ctx = sync_playwright().start()
        # 优先用系统 Chrome（避免依赖 playwright 自带 chromium 下载）
        chrome_path = self._find_system_chrome()
        launch_kwargs = {}
        if chrome_path:
            launch_kwargs["executable_path"] = chrome_path
            _log(f"使用系统 Chrome: {chrome_path}")
        try:
            browser = self._playwright_ctx.chromium.launch(**launch_kwargs)
        except Exception as e:
            _log(f"系统 Chrome 启动失败，回退到自带 chromium: {e}", "WARNING")
            browser = self._playwright_ctx.chromium.launch()
        context = browser.new_context(
            viewport={"width": 1600, "height": 900},
            device_scale_factor=self.config.get("screenshot", {}).get("scale", 2),
        )
        page = context.new_page()
        url = self.input_path.as_uri()
        page.goto(url, wait_until="load")
        # 注入 preview-mode
        preview_mode = self.config.get("preview_mode", "a4-landscape")
        page.evaluate(
            f"localStorage.setItem('sr-preview-mode', '{preview_mode}')"
        )
        page.reload(wait_until="load")
        # 触发分页（可选）
        if self.config.get("trigger_paginate", False):
            page.evaluate("window.paginate && window.paginate()")
        # 等待渲染完成
        wait_cfg = self.config.get("render_wait", {})
        page.wait_for_timeout(wait_cfg.get("after_load_ms", 2000))
        for marker in wait_cfg.get("ready_markers", []):
            try:
                page.wait_for_selector(marker, timeout=10000)
            except Exception as e:
                _log(f"ready_marker 未出现（忽略）: {marker} ({e})", "WARNING")
        self._page = page
        self._browser = browser
        self._context = context
        _log("渲染完成")
        return page

    @staticmethod
    def _find_system_chrome():
        """查找系统已装的 Chrome / Edge 可执行文件路径。"""
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return None

    def close(self):
        if self._playwright_ctx:
            try:
                self._browser.close()
            except Exception:
                pass
            try:
                self._playwright_ctx.stop()
            except Exception:
                pass
            self._playwright_ctx = None

    # ──────────────────────────────────────────────
    # 复杂组件截图
    # ──────────────────────────────────────────────

    @staticmethod
    def _freeze_layout_script():
        """注入脚本：收尾 ECharts 渲染 + 把 .chw 容器尺寸固定为内联样式 + 冻结
        ResizeObserver + 隐藏 nav，避免 Playwright `Locator.screenshot` 在
        scrollIntoView 后元素持续重排导致 30s 超时。

        根因（实测确认）：已存在的 ResizeObserver 实例引用的是原构造器，替换
        `window.ResizeObserver` 不能阻止它们触发 callback；唯一可靠办法是让被
        观察元素的尺寸不再变化。本脚本读出每个 `.chw` 当前的 offsetWidth/Height，
        写为内联 `width/height`，使后续 RO 测得的尺寸恒等于当前值，回调不会再
        触发 echarts 重排。配合隐藏 nav，scrollIntoView 也不会触发 onScroll 修改
        DOM。
        """
        return r"""
        (() => {
          const ret = { resized: 0, observersDisconnected: 0, roReplaced: false,
                        navHidden: false, chwPinned: 0 };
          try {
            // 1) 主动收尾：把所有 .chw 容器上的 ECharts 实例 resize 一次，
            //    让 size 落到当前布局的最终值。
            if (window.echarts) {
              document.querySelectorAll('.chw').forEach((el) => {
                try {
                  const inst = window.echarts.getInstanceByDom(el);
                  if (inst) { inst.resize(); ret.resized += 1; }
                } catch (e) { /* ignore individual chart error */ }
              });
            }
            // 2) 断开已知 donut chart 的 ResizeObserver（__srDonutCleanup）。
            if (window.echarts) {
              document.querySelectorAll('.chw').forEach((el) => {
                try {
                  const inst = window.echarts.getInstanceByDom(el);
                  if (inst && typeof inst.__srDonutCleanup === 'function') {
                    inst.__srDonutCleanup();
                    ret.observersDisconnected += 1;
                  }
                } catch (e) { /* ignore */ }
              });
            }
            // 3) 冻结后续 ResizeObserver：替换 window.ResizeObserver 为 no-op。
            if (window.ResizeObserver) {
              window.__srOrigResizeObserver = window.ResizeObserver;
              window.ResizeObserver = class {
                constructor(cb) { this._cb = cb; }
                observe() {}
                unobserve() {}
                disconnect() {}
              };
              ret.roReplaced = true;
            }
            // 4) 隐藏 nav（nav 本来就在 skip_selectors 中），setActive 即使被
            //    onScroll 调用也无 DOM 可改 class。
            try {
              document.querySelectorAll('.sr-nav-wrap, .sr-nav-rail, .sr-nav').forEach((el) => {
                el.style.display = 'none';
              });
              ret.navHidden = true;
            } catch (e) { /* ignore */ }
            // 5) 关键：把每个 .chw 容器尺寸固定为内联样式。这样被观察元素的
            //    尺寸不再变化，已存在的 RO 实例不会再触发 callback（即使它们
            //    引用的是原构造器）。再调用一次 resize() 让 ECharts 内部画布
            //    与固定后的容器尺寸对齐。
            document.querySelectorAll('.chw').forEach((el) => {
              try {
                const w = el.offsetWidth;
                const h = el.offsetHeight;
                if (w > 0 && h > 0) {
                  el.style.width = w + 'px';
                  el.style.height = h + 'px';
                  ret.chwPinned += 1;
                }
              } catch (e) { /* ignore */ }
            });
            if (window.echarts) {
              document.querySelectorAll('.chw').forEach((el) => {
                try {
                  const inst = window.echarts.getInstanceByDom(el);
                  if (inst) inst.resize();
                } catch (e) { /* ignore */ }
              });
            }
            // 6) 滚回顶部，避免 scrollIntoView 大幅滚动触发更多 listener。
            try { window.scrollTo(0, 0); } catch (e) { /* ignore */ }
          } catch (e) {
            ret.error = String(e);
          }
          return ret;
        })();
        """

    def _freeze_layout_before_snapshot(self, page):
        """截图前冻结布局：收尾 ECharts + 固定 .chw 尺寸 + 隐藏 nav。"""
        try:
            result = page.evaluate(self._freeze_layout_script())
            _log(f"冻结布局: resized={result.get('resized')} "
                 f"observersDisconnected={result.get('observersDisconnected')} "
                 f"roReplaced={result.get('roReplaced')} "
                 f"navHidden={result.get('navHidden')} "
                 f"chwPinned={result.get('chwPinned')} "
                 f"error={result.get('error', 'none')}")
            # 让最后一帧 layout 跑完，再开始截图
            page.wait_for_timeout(300)
        except Exception as e:
            _log(f"冻结布局注入失败（忽略）: {e}", "WARNING")

    def snapshot_complex_components(self, page=None):
        """遍历 snapshot_selectors，逐个截图，返回 {占位 id: 图片路径} 映射。"""
        page = page or self._page
        # 截图前先冻结一次布局：把 ECharts 收尾 + 固定 .chw 容器尺寸 + 隐藏 nav。
        # 循环内每次截图前还会再冻结一次，以应对上一轮 replaceWith 引起的 DOM 变化。
        self._freeze_layout_before_snapshot(page)
        tmp_dir = Path(self.config.get("tmp_dir", "tmp/html_to_word"))
        tmp_dir.mkdir(parents=True, exist_ok=True)
        snapshot_map = {}
        for selector in self.config.get("snapshot_selectors", []):
            try:
                locator = page.locator(selector)
                initial_count = locator.count()
            except Exception as e:
                _log(f"selector 不可用（忽略）: {selector} ({e})", "WARNING")
                continue
            _log(f"截图 selector={selector} count={initial_count}")
            # 关键：每次截图后用 replaceWith 把元素替换为 img 占位，会让该 selector
            # 对应的元素列表少一个。若仍按 range(initial_count) 迭代，第 i 越往后
            # 越容易取不到元素（els[idx] 为 undefined）。改用 while 循环：每次取
            # 第 0 个元素、打标、截图、替换，直到该 selector 下无元素为止。
            # 注意：嵌套选择器（如 .sr-chart-card 嵌在 .sr-chart-slot 内）会随外层
            # 替换而消失，循环会自然提前结束——这是预期行为（外层 slot 已截图覆盖）。
            captured = 0
            while True:
                # 截图前先冻结布局：上一轮 replaceWith 会改变 DOM 结构，可能导致
                # 剩余 .chw 容器尺寸变化、ECharts 重排。重新跑一次冻结脚本把剩余
                # 容器尺寸固定到当前值，确保截图时 bounding box 稳定。
                self._freeze_layout_before_snapshot(page)
                snap_id = f"sr-snap-{self._snapshot_index}"
                self._snapshot_index += 1
                # 给当前 selector 下第 0 个元素打 data-snapshot-id 标记
                try:
                    marked = page.evaluate(
                        """([sel, sid]) => {
                            const el = document.querySelector(sel);
                            if (!el) return false;
                            el.setAttribute('data-snapshot-id', sid);
                            return true;
                        }""",
                        [selector, snap_id],
                    )
                except Exception as e:
                    _log(f"打标失败（忽略）: {selector} ({e})", "WARNING")
                    break
                if not marked:
                    # 该 selector 下已无元素，结束循环
                    break
                # 用 data-snapshot-id 精确定位（不受 replaceWith 索引偏移影响）
                el = page.locator(f'[data-snapshot-id="{snap_id}"]')
                img_path = tmp_dir / f"comp-{snap_id}.png"
                try:
                    el.screenshot(path=str(img_path))
                except Exception as e:
                    _log(f"截图失败（忽略）: {selector}#{captured} ({e})", "WARNING")
                    # 截图失败也要清理标记，避免影响后续
                    try:
                        page.evaluate(
                            """(sid) => {
                                const el = document.querySelector(`[data-snapshot-id="${sid}"]`);
                                if (el) el.removeAttribute('data-snapshot-id');
                            }""",
                            snap_id,
                        )
                    except Exception:
                        pass
                    # 即使截图失败也把元素替换为空 img，避免下一轮 while 又取到同一元素死循环
                    try:
                        page.evaluate(
                            """([sel, sid]) => {
                                const el = document.querySelector(`[data-snapshot-id="${sid}"]`)
                                    || document.querySelector(sel);
                                if (!el) return;
                                const img = document.createElement('img');
                                img.setAttribute('data-snapshot', sid);
                                img.setAttribute('alt', 'chart');
                                img.style.maxWidth = '100%';
                                el.replaceWith(img);
                            }""",
                            [selector, snap_id],
                        )
                    except Exception:
                        pass
                    continue
                # 替换为 img 占位：通过 data-snapshot-id 定位
                try:
                    page.evaluate(
                        """(sid) => {
                            const el = document.querySelector(`[data-snapshot-id="${sid}"]`);
                            if (!el) return;
                            const img = document.createElement('img');
                            img.setAttribute('data-snapshot', sid);
                            img.setAttribute('alt', 'chart');
                            img.style.maxWidth = '100%';
                            el.replaceWith(img);
                        }""",
                        snap_id,
                    )
                except Exception as e:
                    _log(f"DOM 替换失败（忽略）: {selector}#{captured} ({e})", "WARNING")
                    continue
                snapshot_map[snap_id] = str(img_path)
                captured += 1
            _log(f"selector={selector} 实际截图 {captured}/{initial_count} 个")
        _log(f"截图完成: {len(snapshot_map)} 个组件")
        self._snapshot_map = snapshot_map
        return snapshot_map

    # ──────────────────────────────────────────────
    # DOM 提取
    # ──────────────────────────────────────────────

    def extract_dom(self, page=None):
        """page.content() → BeautifulSoup。返回根节点（按 dom_root 选择）。"""
        page = page or self._page
        html = page.content()
        soup = BeautifulSoup(html, "lxml")
        root_sel = self.config.get("dom_root", "#sr-page-source")
        if root_sel.startswith("#"):
            root = soup.find(id=root_sel[1:])
        else:
            root = soup.select_one(root_sel)
        if root is None:
            _log(f"dom_root 未找到，回退到 <body>", "WARNING")
            root = soup.body or soup
        # 封面 .sr-cover 在 dom_root 之外（HTML 中作为页面顶层 header 存在），
        # 此处先从 soup 抓取并缓存，避免 _extract_cover_info 在 root 内找不到。
        self._cover_node = soup.select_one(".sr-cover")
        # 文档信息页 .sr-doc-info-page 在 dom_root 之内，但要单独成页并排在 TOC 前，
        # 此处先从 soup 抓取并缓存，避免正文流里重复映射。
        self._doc_info_node = soup.select_one(".sr-doc-info-page")
        # 剔除 skip_selectors 节点
        for sel in self.config.get("skip_selectors", []):
            for node in root.select(sel):
                node.decompose()
        # 剔除 HTML 注释（浏览器不渲染，但 NavigableString 分支会把它当文本
        # 提取并写入 Word，导致 "TOP5 风险详情行：#01/#02 typePhrase 动态规则
        # 见 安全体检报告2.0-需求与交互设计评审.md §P4 §4.1 延伸盘点" 这类
        # 设计文档注释出现在正文里）
        for c in root.find_all(string=lambda s: isinstance(s, Comment)):
            c.extract()
        # 剔除 script / style / noscript
        for tag in root.find_all(["script", "style", "noscript"]):
            tag.decompose()
        # 剔除 data-hide="true" 元素（HTML 预览中被 CSS [data-hide="true"]{display:none}
        # 隐藏的内容，如占位符列表项、无需展示的风险卡等，浏览器不渲染，Word 也不应出现）
        for tag in root.find_all(attrs={"data-hide": "true"}):
            tag.decompose()
        return root

    # ──────────────────────────────────────────────
    # docx 拼装
    # ──────────────────────────────────────────────

    def assemble_docx(self, root, snapshot_map, output_path=None):
        """创建 docx，遍历 DOM 映射，保存。"""
        # 防御性剔除 skip_selectors（即使调用方未走 extract_dom）
        for sel in self.config.get("skip_selectors", []):
            try:
                for node in root.select(sel):
                    node.decompose()
            except Exception:
                pass
        for tag in root.find_all(["script", "style", "noscript"]):
            tag.decompose()
        # 防御性剔除 HTML 注释（同 extract_dom）
        for c in root.find_all(string=lambda s: isinstance(s, Comment)):
            c.extract()
        # 防御性剔除 data-hide="true" 元素（同 extract_dom）
        try:
            for tag in root.find_all(attrs={"data-hide": "true"}):
                tag.decompose()
        except Exception:
            pass
        doc = Document()
        self._configure_page(doc)
        # 首页：A4 竖版封面（背景图固定使用 html_to_word/assets/a4-portrait-bg.png）
        # 必须在正文 section 配置之后、TOC 之前插入；插入完成后用 section break
        # 切换回正文 section（A4 横版）。
        cover_info = self._extract_cover_info(root)
        self._insert_cover_page(doc, cover_info)
        # 切换到正文 section：在封面后新增一个 next-page section break，恢复横版
        self._switch_to_body_section(doc)
        # 文档信息页：单独成页，排在 TOC 前
        self._insert_doc_info_page(doc)
        # 在正文 section 开头插入目录（TOC 域）
        self._insert_toc(doc, levels="1-3")
        container = _Container(doc, fonts=self.config.get("fonts", {}) or {})
        self._map_children(root, container)
        out = Path(output_path) if output_path else self.output_path
        out.parent.mkdir(parents=True, exist_ok=True)
        # 在 settings.xml 写入 <w:updateFields w:val="true"/>，Word 打开文档时
        # 会自动提示更新所有域（包含 TOC），用户点"是"即可填充真实目录。
        self._enable_update_fields_on_open(doc)
        doc.save(str(out))
        _log(f"已保存 docx: {out}")
        # 在 save 之后调用 Word COM 离线刷新所有域（TOC / PAGE / REF），
        # 让用户拿到的 docx 自带真实目录与页码。无 Word 时回退到上面的开关模式。
        try:
            self._update_fields_via_word(out)
        except Exception as e:
            _log(f"更新域流程异常（docx 已保存可用）: {e}", "WARNING")
        return out

    @staticmethod
    def _enable_update_fields_on_open(doc):
        """在 settings.xml 中写入 <w:updateFields w:val="true"/>，让 Word 打开
        文档时自动更新所有域（TOC 等动态字段）。

        关键：CT_Settings schema 对子元素顺序有严格要求，<w:updateFields> 必须位于
        <w:rsids> 之前、<w:compat> 之后（具体顺序参见 ECMA-376 第 17.15.1.75 节
        附近的 schema 序列）。直接 append 到末尾会被某些 Word 版本忽略。
        这里按正确顺序插入。

        Word 行为：检测到该开关后，打开文档时弹"此文档包含可能引用其他文件的
        字段。是否更新此文档中的字段？"提示，点"是"即更新目录。
        """
        settings = doc.settings.element
        # 避免重复添加
        existing = settings.find(qn("w:updateFields"))
        if existing is not None:
            existing.set(qn("w:val"), "true")
            return
        upd = OxmlElement("w:updateFields")
        upd.set(qn("w:val"), "true")
        # 按 CT_Settings 顺序，updateFields 应在 rsids 之前。找 rsids 锚点插入
        rsids = settings.find(qn("w:rsids"))
        if rsids is not None:
            rsids.addprevious(upd)
            return
        # 回退：找 compat 锚点之后插入
        compat = settings.find(qn("w:compat"))
        if compat is not None:
            compat.addnext(upd)
            return
        # 最终回退：append 到末尾
        settings.append(upd)

    def _update_fields_via_word(self, out_path):
        """在 doc.save() 之后调用 Word COM 离线刷新所有域（TOC / PAGE / REF 等）。

        读取 config["update_fields_after_save"]：
          - enabled: 是否启用
          - backend: win32com（MS Word） / wps（Kwps.Application） / none
          - timeout_sec: COM 调用整体超时
          - fail_silently: 失败时仅告警不抛

        关键点：
          1. COM 调用必须 try/except/finally，确保 word.Quit() 一定执行，
             否则 Word 进程会泄漏卡死后续自动化。
          2. Word 单实例 + 文件被占用时会冲突，调用前用 os.open 独占尝试检测；
             被占用则跳过 COM，回退到 settings.xml 开关模式。
          3. 更新顺序：doc.Fields.Update → 遍历 TablesOfContents 逐个 Update →
             doc.Repaginate → doc.Save，确保页码与目录条目都已写入磁盘。
        """
        cfg = self.config.get("update_fields_after_save") or {}
        if not cfg.get("enabled", False):
            _log("update_fields_after_save.enabled=false，跳过 COM 更新域")
            return False
        backend = (cfg.get("backend") or "none").lower()
        if backend == "none":
            return False
        fail_silently = bool(cfg.get("fail_silently", True))
        timeout_sec = int(cfg.get("timeout_sec", 60) or 60)

        # 文件占用检测：用 os.open 以共享写方式探测，被独占则跳过 COM。
        # 注意：不能用 O_EXCL（文件已存在时本就返回 EEXIST，逻辑反了）。
        # Windows 上 os.open 默认不共享，被 Word/WPS 持有时会抛 PermissionError。
        try:
            fd = os.open(str(out_path), os.O_RDWR)
            os.close(fd)
        except OSError:
            _log(f"docx 已被占用，跳过 COM 更新域: {out_path}", "WARNING")
            return False

        # 迟延导入，避免无 pywin32 环境直接 ImportError
        try:
            import win32com.client as _w32c  # noqa: F401
            import pythoncom  # noqa: F401
        except ImportError:
            msg = "pywin32 未安装，无法调用 Word COM 更新域；回退到 settings.xml 开关模式"
            if fail_silently:
                _log(msg, "WARNING")
                return False
            raise

        progid = "Word.Application" if backend == "win32com" else "Kwps.Application"
        word = None
        doc = None
        try:
            pythoncom.CoInitialize()
            word = _w32c.DispatchEx(progid)
            try:
                word.Visible = False
            except Exception:
                pass
            try:
                word.DisplayAlerts = 0  # wdAlertsNone
            except Exception:
                pass

            # Word 2007 等老版本对相对路径 / 正斜杠的 Documents.Open 不稳定，
            # 会触发 Office 文件打开子组件调用系统注册的 Shell Hook（WPS 安装残留
            # 仍可能注册），导致异常 source 标为 'Kingsoft WPS'、错误码 3010
            # '文档打开失败'。强制转绝对路径 + 反斜杠避开该路径。
            abs_win_path = os.path.abspath(str(out_path)).replace("/", "\\")
            doc = word.Documents.Open(abs_win_path, ReadOnly=False)

            # 更新所有域
            try:
                doc.Fields.Update()
            except Exception as e:
                _log(f"Fields.Update 异常: {e}", "WARNING")

            # 优先更新 TOC（如果存在）
            toc_count = 0
            try:
                tocs = doc.TablesOfContents
                toc_count = tocs.Count
                for i in range(1, toc_count + 1):
                    try:
                        tocs(i).Update()
                    except Exception as e:
                        _log(f"TOC[{i}].Update 异常: {e}", "WARNING")
            except Exception as e:
                _log(f"TablesOfContents 访问异常: {e}", "WARNING")

            # 重新分页确保页码刷新
            try:
                doc.Repaginate()
            except Exception as e:
                _log(f"Repaginate 异常: {e}", "WARNING")

            # 保存（用原格式，避免触发 SaveAs 转换对话框）
            try:
                doc.Save()
            except Exception as e:
                _log(f"doc.Save 异常: {e}", "WARNING")

            _log(f"Word COM 已更新域（TOC: {toc_count}）: {out_path}")
            return True
        except Exception as e:
            msg = f"Word COM 更新域失败 [{backend}]: {e}"
            if fail_silently:
                _log(msg, "WARNING")
                return False
            raise
        finally:
            try:
                if doc is not None:
                    doc.Close(SaveChanges=0)
            except Exception:
                pass
            try:
                if word is not None:
                    word.Quit()
            except Exception:
                pass
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass


    def _insert_toc(self, doc, levels="1-3"):
        """在文档开头插入目录（TOC 域），标题"目录"为普通段落。

        生成的结构：
          段落1：标题"目录"（居中、加粗、Heading 1 样式以方便识别）
          段落2：TOC 域（fldChar begin → instrText 'TOC \\o "1-3" \\h \\z' →
                  fldChar separate → 占位文本 → fldChar end）
        Word 打开后会提示"更新域"，或用户右键→更新域，即可填充真实目录。
        """
        # 标题段
        title_p = doc.add_paragraph()
        title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        title_run = title_p.add_run("目录")
        title_run.bold = True
        title_run.font.size = Pt(18)

        # TOC 域段
        toc_p = doc.add_paragraph()
        # 域开始：标记 w:dirty="true"，让 Word 打开时自动重算该域。
        run_begin = toc_p.add_run()
        fld_begin = OxmlElement("w:fldChar")
        fld_begin.set(qn("w:fldCharType"), "begin")
        fld_begin.set(qn("w:dirty"), "true")
        run_begin._element.append(fld_begin)

        # 域指令
        run_instr = toc_p.add_run()
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = f' TOC \\o "{levels}" \\h \\z '
        run_instr._element.append(instr)

        # 域分隔
        run_sep = toc_p.add_run()
        fld_sep = OxmlElement("w:fldChar")
        fld_sep.set(qn("w:fldCharType"), "separate")
        run_sep._element.append(fld_sep)

        # 占位文本（Word 打开后会被替换）
        run_placeholder = toc_p.add_run("（右键此处选择“更新域”以生成目录）")
        run_placeholder.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

        # 域结束
        run_end = toc_p.add_run()
        fld_end = OxmlElement("w:fldChar")
        fld_end.set(qn("w:fldCharType"), "end")
        run_end._element.append(fld_end)

        # 在目录后插入分页符，让正文从新页开始
        page_break_p = doc.add_paragraph()
        pb_run = page_break_p.add_run()
        br = OxmlElement("w:br")
        br.set(qn("w:type"), "page")
        pb_run._element.append(br)

    def _insert_doc_info_page(self, doc):
        """插入文档信息页：把缓存的 .sr-doc-info-page 节点映射到正文 section，
        末尾插分页符让其单独成页，排在 TOC 前。

        节点结构：
          <section class="sr-doc-info-page">
            <h2>版权申明</h2>
            <p>本文档...</p>
            <h3>文档信息</h3>
            <table class="sr-tbl sr-copyright-meta">...</table>
          </section>
        """
        node = getattr(self, "_doc_info_node", None)
        if node is None:
            _log("未找到 .sr-doc-info-page 节点，跳过文档信息页插入", "WARNING")
            return
        fonts_cfg = self.config.get("fonts", {}) or {}
        container = _Container(doc, fonts=fonts_cfg)
        # 按顺序映射直接子节点（h2 / p / h3 / table）
        # h2/h3 用普通段落写入并手动设格式，避免被 TOC 自动收录
        for child in node.children:
            if child.name in ('h2', 'h3'):
                text = child.get_text(" ", strip=True)
                if text:
                    cfg_key = 'heading_2' if child.name == 'h2' else 'heading_3'
                    cfg = fonts_cfg.get(cfg_key, {})
                    p = container.add_paragraph(text)
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    pf = p.paragraph_format
                    pf.space_before = Pt(cfg.get('space_before_pt', 0))
                    pf.space_after = Pt(cfg.get('space_after_pt', 0))
                    for run in p.runs:
                        run.bold = cfg.get('bold', True)
                        # 局部覆盖：版权申明/文档信息标题固定为四号（14pt）
                        if (child.name == 'h2' and '版权申明' in text) or                            (child.name == 'h3' and '文档信息' in text):
                            run.font.size = Pt(14)
                        else:
                            run.font.size = Pt(cfg.get('size_pt', 16))
                        color_hex = cfg.get('color_hex', '')
                        if color_hex and len(color_hex) == 6:
                            run.font.color.rgb = RGBColor(
                                int(color_hex[0:2], 16),
                                int(color_hex[2:4], 16),
                                int(color_hex[4:6], 16)
                            )
            else:
                self._map_node(child, container)
                # 版权申明正文：微软雅黑 小四（12pt）
                if child.name == 'p':
                    last_p = container.doc.paragraphs[-1] if not container.is_cell else None
                    if last_p:
                        for run in last_p.runs:
                            run.font.name = '微软雅黑'
                            run.font.size = Pt(12)
                            rpr = run._element.get_or_add_rPr()
                            rFonts = rpr.find(qn('w:rFonts'))
                            if rFonts is None:
                                rFonts = OxmlElement('w:rFonts')
                                rpr.insert(0, rFonts)
                            rFonts.set(qn('w:eastAsia'), '微软雅黑')
        # 末尾插分页符，让 TOC 从新页开始
        page_break_p = doc.add_paragraph()
        pb_run = page_break_p.add_run()
        br = OxmlElement("w:br")
        br.set(qn("w:type"), "page")
        pb_run._element.append(br)

    # ── 首页（封面）──────────────────────────────────

    def _extract_cover_info(self, root):
        """从 DOM root 中提取封面信息（标题、客户名、报告时间）。

        HTML 结构：
          <header class="sr-cover" id="report-top">
            ...
            <h1 class="report-cover-title-main" data-field="cover.title">...</h1>
            ...
            <span class="sr-cover-meta-label">客户名称</span>
            <span class="report-cover-title-sub" data-field="cover.clientName">...</span>
            ...
            <span class="sr-cover-meta-label">报告时间</span>
            <span class="report-cover-desc" data-field="cover.period">...</span>
          </header>
        返回 dict: {title, client_name, period}；找不到的项为空字符串。
        封面节点 .sr-cover 在 dom_root 之外，extract_dom 时已缓存到 self._cover_node。
        """
        info = {"title": "", "client_name": "", "period": ""}
        cover = getattr(self, "_cover_node", None) or (root.select_one(".sr-cover") if root else None)
        if cover is None:
            return info

        def _text(sel):
            el = cover.select_one(sel)
            return el.get_text(strip=True) if el else ""

        info["title"] = _text(".report-cover-title-main")
        info["client_name"] = _text(".report-cover-title-sub")
        info["period"] = _text(".report-cover-desc")
        return info

    def _cover_bg_path(self):
        """封面背景图固定路径：html_to_word/assets/a4-portrait-bg.png"""
        return Path(__file__).resolve().parent / "assets" / "a4-portrait-bg.png"

    def _insert_cover_page(self, doc, cover_info):
        """把第一个 section 改成 A4 竖版、零边距，铺满背景图，标题/客户名/时间
        悬浮在背景图之上。

        实现要点：背景图作为"衬于文字下方"的浮动图片（wp:anchor + behindDoc=1）
        绝对定位到页面 (0,0)、extent=整页大小，与页面边距无关。随后插入的标题/
        客户名/报告时间段落是普通段落，它们流式排列但因为图片浮于文字下方，
        视觉上叠加在背景图之上。

        doc.sections[0] 默认存在；将其重配为 A4 竖版（210×297mm，零边距）作为封面 section。
        """
        bg_path = self._cover_bg_path()
        if not bg_path.exists():
            _log(f"封面背景图不存在: {bg_path}", "WARNING")
        section = doc.sections[0]
        section.orientation = WD_ORIENT.PORTRAIT
        section.page_width = Mm(210)
        section.page_height = Mm(297)
        section.left_margin = Mm(0)
        section.right_margin = Mm(0)
        section.top_margin = Mm(0)
        section.bottom_margin = Mm(0)

        # 插入背景图（浮动、衬于文字下方、占满整页）。即使后续段落存在，背景图
        # 也位于 z-order 最底层，文字悬浮其上。
        if bg_path.exists():
            try:
                self._add_floating_background_picture(doc, str(bg_path),
                                                    page_w_mm=210, page_h_mm=297)
            except Exception as e:
                _log(f"封面背景图插入失败: {e}", "WARNING")

        # 顶部留白把标题/客户名/时间整体推到页面底部
        self._add_cover_spacer(doc, mm_before=200)
        title = cover_info.get("title", "").strip()
        if title:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(title)
            run.bold = True
            run.font.size = Pt(28)
            run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)
        # 客户名 / 报告时间，悬浮在背景图上方（黑色字），位于标题下方
        self._add_cover_spacer(doc, mm_before=10)
        client = cover_info.get("client_name", "").strip()
        if client:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(f"{client}")
            run.font.size = Pt(14)
            run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)
        period = cover_info.get("period", "").strip()
        if period:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(f"{period}")
            run.font.size = Pt(14)
            run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)

    def _add_floating_background_picture(self, doc, image_path, page_w_mm, page_h_mm):
        """插入一张浮动图片：behindDoc=1（衬于文字下方），绝对定位到页面
        (0,0)，extent=整页大小。后续段落流式排列但视觉上叠加在图片之上。

        python-docx 的 add_picture 默认生成 <wp:inline>，需要后处理为
        <wp:anchor>。做法：先用 add_picture 创建 inline 图片段落，再读取
        该段落的 <wp:inline>，转换为 <wp:anchor> 并补充 behindDoc/positionH/
        positionV/extent/simplePos 子元素。
        """
        from PIL import Image as _PILImage
        # 计算图片实际比例，按"完整覆盖页面"等比缩放
        with _PILImage.open(image_path) as im:
            px_w, px_h = im.size
        img_w_mm = px_w * 25.4 / 96.0
        img_h_mm = px_h * 25.4 / 96.0
        scale = max(page_w_mm / img_w_mm, page_h_mm / img_h_mm)
        final_w_emu = int(Mm(img_w_mm * scale).emu)
        final_h_emu = int(Mm(img_h_mm * scale).emu)

        # 1) 先用 add_picture 插入内嵌图片，获得包含 <wp:inline> 的段落
        pic_para = doc.add_paragraph()
        run = pic_para.add_run()
        run.add_picture(image_path, width=Mm(img_w_mm * scale), height=Mm(img_h_mm * scale))

        # 2) 找到 <wp:inline> 元素，转换为 <wp:anchor>
        r = run._element
        drawing = r.find(qn("w:drawing"))
        if drawing is None:
            _log("未找到 w:drawing，背景图插入回退", "WARNING")
            return
        inline = drawing.find(qn("wp:inline"))
        if inline is None:
            _log("未找到 wp:inline，背景图插入回退", "WARNING")
            return

        # 构建 <wp:anchor> 元素，设置 behindDoc=1，把图片衬于文字下方
        nsmap_qn = qn
        anchor = OxmlElement("wp:anchor")
        anchor.set("distT", "0")
        anchor.set("distB", "0")
        anchor.set("distL", "0")
        anchor.set("distR", "0")
        anchor.set("simplePos", "0")
        anchor.set("relativeHeight", "0")
        anchor.set("behindDoc", "1")
        anchor.set("locked", "0")
        anchor.set("layoutInCell", "1")
        anchor.set("allowOverlap", "1")

        # simplePos 元素（必须存在但 simplePos=0 时被忽略）
        simple_pos = OxmlElement("wp:simplePos")
        simple_pos.set("x", "0")
        simple_pos.set("y", "0")
        anchor.append(simple_pos)

        # positionH：相对 page，偏移 0
        pos_h = OxmlElement("wp:positionH")
        pos_h.set("relativeFrom", "page")
        pos_offset = OxmlElement("wp:posOffset")
        pos_offset.text = "0"
        pos_h.append(pos_offset)
        anchor.append(pos_h)

        # positionV：相对 page，偏移 0
        pos_v = OxmlElement("wp:positionV")
        pos_v.set("relativeFrom", "page")
        pos_offset_v = OxmlElement("wp:posOffset")
        pos_offset_v.text = "0"
        pos_v.append(pos_offset_v)
        anchor.append(pos_v)

        # extent：图片最终大小
        extent = OxmlElement("wp:extent")
        extent.set("cx", str(final_w_emu))
        extent.set("cy", str(final_h_emu))
        anchor.append(extent)

        # effectExtent（占位）
        effect_extent = OxmlElement("wp:effectExtent")
        effect_extent.set("l", "0")
        effect_extent.set("t", "0")
        effect_extent.set("r", "0")
        effect_extent.set("b", "0")
        anchor.append(effect_extent)

        # wrapNone：让文字穿过图片（图片不占用段落空间）
        wrap_none = OxmlElement("wp:wrapNone")
        anchor.append(wrap_none)

        # docPr
        doc_pr = OxmlElement("wp:docPr")
        doc_pr.set("id", "0")
        doc_pr.set("name", "背景图")
        anchor.append(doc_pr)

        # cNvGraphicFramePr（占位）
        cnv = OxmlElement("wp:cNvGraphicFramePr")
        anchor.append(cnv)

        # 把原 <wp:inline> 的 <a:graphic> 子元素搬到 <wp:anchor> 下
        graphic = inline.find(qn("a:graphic"))
        if graphic is not None:
            anchor.append(graphic)

        # 替换 inline 为 anchor
        drawing.remove(inline)
        drawing.append(anchor)

        # 让该段落自身不占用额外空间（行高最小）
        pf = pic_para.paragraph_format
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.line_spacing = 1.0

    @staticmethod
    def _add_cover_spacer(doc, mm_before):
        """插入空白段，用前置间距把后续内容往下推 mm_before 毫米。"""
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        # 用前置间距实现下移
        from docx.shared import Mm as _Mm
        pf.space_before = _Mm(mm_before)
        return p

    def _switch_to_body_section(self, doc):
        """在封面后新增 next-page section，作为正文 section（A4 竖版，与封面统一）。

        python-docx: doc.add_section(WD_SECTION.NEW_PAGE) 会插入分节符并新增 section。
        之后把新 section 的页面尺寸/边距重新设为正文（A4 竖版），并清掉新 section
        继承的页眉页脚链接以避免影响正文。
        """
        from docx.enum.section import WD_SECTION
        new_section = doc.add_section(WD_SECTION.NEW_PAGE)
        cfg = self.config.get("docx", {})
        w = Mm(cfg.get("page_width_mm", 210))
        h = Mm(cfg.get("page_height_mm", 297))
        m = Mm(cfg.get("margin_mm", 20))
        new_section.orientation = WD_ORIENT.PORTRAIT
        new_section.page_width = w
        new_section.page_height = h
        new_section.left_margin = m
        new_section.right_margin = m
        new_section.top_margin = m
        new_section.bottom_margin = m
        return new_section

    def _configure_page(self, doc):
        """设置 A4 竖版页面与边距。"""
        cfg = self.config.get("docx", {})
        w = Mm(cfg.get("page_width_mm", 210))
        h = Mm(cfg.get("page_height_mm", 297))
        m = Mm(cfg.get("margin_mm", 20))
        section = doc.sections[0]
        section.orientation = WD_ORIENT.PORTRAIT
        section.page_width = w
        section.page_height = h
        section.left_margin = m
        section.right_margin = m
        section.top_margin = m
        section.bottom_margin = m
        # 正文默认字体（应用 fonts.normal 配置）
        fonts_cfg = self.config.get("fonts", {}) or {}
        self._apply_font_style(doc.styles["Normal"], fonts_cfg.get("normal", {}))
        # 关闭 Heading 1~6 的自动编号：HTML 中已带手写序号（"1." "3.1" "4.1.1"），
        # Word 内置 Heading 样式默认链接到多级列表 numId，会叠加出双序号。
        # 这里直接从样式定义里删除 numPr，并在每个 add_heading 调用后再做一次兜底
        # 清理（见 _strip_paragraph_num_pr）。
        # 同时应用 fonts.heading_1~6 配置（字体/字号/颜色/加粗/间距）。
        for lvl in range(1, 7):
            try:
                hs = doc.styles[f"Heading {lvl}"]
                self._strip_style_num_pr(hs)
                self._apply_font_style(hs, fonts_cfg.get(f"heading_{lvl}", {}))
            except KeyError:
                continue
        # Normal 也要兜底清掉 numPr，避免某些模板默认带 List Number 段落样式
        self._strip_style_num_pr(doc.styles["Normal"])

    @staticmethod
    def _apply_font_style(style, cfg):
        """把 fonts.* 配置段应用到 docx 样式对象。

        支持字段：
          - font:        拉丁字体名（style.font.name）
          - east_asia:   东亚字体名（w:eastAsia）
          - size_pt:     字号（磅）
          - bold:        是否加粗
          - italic:      是否斜体
          - color_hex:   字体颜色（RRGGBB，不带 #）
          - space_before_pt / space_after_pt: 段前/段后间距（磅）
          - line_spacing_pt: 行距（磅）
        缺省字段不覆盖，保留 docx 模板默认。
        """
        if not cfg:
            return
        font = style.font
        if "font" in cfg and cfg["font"]:
            font.name = cfg["font"]
        if "size_pt" in cfg and cfg["size_pt"] is not None:
            font.size = Pt(cfg["size_pt"])
        if "bold" in cfg and cfg["bold"] is not None:
            font.bold = cfg["bold"]
        if "italic" in cfg and cfg["italic"] is not None:
            font.italic = cfg["italic"]
        if "color_hex" in cfg and cfg["color_hex"]:
            try:
                font.color.rgb = RGBColor.from_string(cfg["color_hex"])
            except (ValueError, AttributeError):
                _log(f"无效的 color_hex: {cfg['color_hex']}", "WARNING")
        # 东亚字体：写入 rFonts/@w:eastAsia
        if "east_asia" in cfg and cfg["east_asia"]:
            rPr = style.element.get_or_add_rPr()
            rFonts = rPr.find(qn("w:rFonts"))
            if rFonts is None:
                rFonts = OxmlElement("w:rFonts")
                rPr.append(rFonts)
            # 清除主题字体引用，避免 Word 渲染中文时 fallback 到主题字体
            # （python-docx 默认模板 majorFont/Jpan=MS Gothic、Hans=宋体，
            #  仅追加显式 w:eastAsia 不删 asciiTheme/eastAsiaTheme 等
            #  主题引用属性时，部分字符仍会被 Word 按 Unicode script 归到
            #  主题字体）。同时设置 ascii/hAnsi，让英文字符也走显式字体名。
            for theme_attr in ("asciiTheme", "hAnsiTheme", "eastAsiaTheme", "cstheme"):
                if rFonts.get(qn(f"w:{theme_attr}")) is not None:
                    del rFonts.attrib[qn(f"w:{theme_attr}")]
            rFonts.set(qn("w:eastAsia"), cfg["east_asia"])
            # 若配置同时提供拉丁字体名，则一并写入 ascii/hAnsi，避免英文 fallback
            if "font" in cfg and cfg["font"]:
                rFonts.set(qn("w:ascii"), cfg["font"])
                rFonts.set(qn("w:hAnsi"), cfg["font"])
        # 段落间距
        pf = style.paragraph_format
        if "space_before_pt" in cfg and cfg["space_before_pt"] is not None:
            pf.space_before = Pt(cfg["space_before_pt"])
        if "space_after_pt" in cfg and cfg["space_after_pt"] is not None:
            pf.space_after = Pt(cfg["space_after_pt"])
        if "line_spacing_pt" in cfg and cfg["line_spacing_pt"] is not None:
            pf.line_spacing = Pt(cfg["line_spacing_pt"])

    @staticmethod
    def _strip_style_num_pr(style):
        """从样式定义中移除 w:numPr，避免该样式下的段落继承自动编号。"""
        pPr = style.element.get_or_add_pPr()
        if pPr is None:
            return
        for tag in ("w:numPr",):
            el = pPr.find(qn(tag))
            if el is not None:
                pPr.remove(el)

    @staticmethod
    def _strip_paragraph_num_pr(paragraph):
        """清除单个段落上的自动编号（numPr），保留文本中已手写的序号。"""
        pPr = paragraph._p.get_or_add_pPr()
        for el in pPr.findall(qn("w:numPr")):
            pPr.remove(el)

    # ──────────────────────────────────────────────
    # DOM → docx 元素映射
    # ──────────────────────────────────────────────

    def _map_children(self, parent_tag, container, depth=0):
        """深度优先遍历 parent_tag 的直接子节点，映射到 docx。"""
        for child in parent_tag.children:
            self._map_node(child, container, depth)

    def _map_node(self, node, container, depth=0):
        """映射单个 DOM 节点到 docx。container 是 _Container。"""
        if isinstance(node, NavigableString):
            text = str(node).strip()
            if text:
                container.add_paragraph(text)
            return
        if not isinstance(node, Tag):
            return
        if getattr(node, "name", None) is None:
            return
        # 封面 .sr-cover 已在 _insert_cover_page 中作为独立 section 渲染，
        # 此处跳过避免正文流里重复出现。
        if node.name == "header" and "sr-cover" in (node.get("class") or []):
            return
        # 文档信息页 .sr-doc-info-page 已在 _insert_doc_info_page 中单独渲染，
        # 此处跳过避免正文流里重复出现。
        if node.name == "section" and "sr-doc-info-page" in (node.get("class") or []):
            return
        # 检查 class 匹配的 style_map 项（优先于标签）
        handler = self._lookup_style_handler(node)
        if handler:
            handler(node, container)
            return
        name = node.name
        if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._map_heading(node, container, level=int(name[1]))
        elif name == "p":
            self._map_paragraph(node, container)
        elif name == "table":
            self._map_table(node, container)
        elif name == "ul":
            self._map_list(node, container, ordered=False)
        elif name == "ol":
            self._map_list(node, container, ordered=True)
        elif name == "img":
            self._map_image(node, container)
        elif name in ("div", "section", "header", "article", "aside", "main", "footer", "figure", "figcaption"):
            # 容器节点：递归处理子节点
            self._map_children(node, container, depth + 1)
        elif name in ("span", "strong", "em", "b", "i", "a", "small", "sub", "sup", "label"):
            text = node.get_text(" ", strip=True)
            if text:
                p = container.add_paragraph()
                run = p.add_run(text)
                if name in ("strong", "b"):
                    run.bold = True
                elif name in ("em", "i"):
                    run.italic = True
        elif name in ("br", "hr"):
            container.add_paragraph("")
        else:
            text = node.get_text(" ", strip=True)
            if text:
                container.add_paragraph(text)

    def _lookup_style_handler(self, node):
        """根据 style_map 查找自定义 handler。命中类名优先。"""
        sm = self.config.get("style_map", {})
        classes = node.get("class") or []
        for cls in classes:
            key = f".{cls}"
            if key in sm:
                handler_name = sm[key]
                handler = getattr(self, f"_handle_{handler_name}", None)
                if handler:
                    return handler
        if node.name in sm:
            handler_name = sm[node.name]
            return getattr(self, f"_handle_{handler_name}", None)
        return None

    # ── 具体映射函数 ─────────────────────────────────

    def _handle_heading_1(self, node, container): self._map_heading(node, container, level=1)
    def _handle_heading_2(self, node, container): self._map_heading(node, container, level=2)
    def _handle_heading_3(self, node, container): self._map_heading(node, container, level=3)
    def _handle_heading_4(self, node, container): self._map_heading(node, container, level=4)
    def _handle_heading_5(self, node, container): self._map_heading(node, container, level=5)
    def _handle_heading_6(self, node, container): self._map_heading(node, container, level=6)
    def _handle_paragraph(self, node, container): self._map_paragraph(node, container)
    def _handle_table(self, node, container): self._map_table(node, container)
    def _handle_bullet_list(self, node, container): self._map_list(node, container, ordered=False)
    def _handle_number_list(self, node, container): self._map_list(node, container, ordered=True)
    def _handle_image(self, node, container): self._map_image(node, container)

    def _handle_risk_card_table(self, node, container):
        """风险卡：用单行单列表格 + 内部段落近似还原。"""
        card_table = container.add_table(rows=1, cols=1)
        cell = card_table.cell(0, 0)
        cell_container = _Container(container.doc, cell=cell, fonts=container.fonts)
        for child in node.children:
            if isinstance(child, Tag) and child.name in ("h6", "h5", "h4"):
                head_text = child.get_text(strip=True)
                p = cell_container.add_paragraph()
                run = p.add_run(head_text)
                run.bold = True
            elif isinstance(child, Tag):
                self._map_node(child, cell_container)
        self._set_table_borders(card_table)

    def _handle_kpi_paragraph(self, node, container):
        """KPI 卡：用加粗大字段落。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        p = container.add_paragraph()
        run = p.add_run(text)
        run.bold = True
        run.font.size = Pt(14)

    def _handle_tag_critical(self, node, container): self._map_tag(node, container, "tag_critical")
    def _handle_tag_high(self, node, container): self._map_tag(node, container, "tag_high")
    def _handle_tag_medium(self, node, container): self._map_tag(node, container, "tag_medium")
    def _handle_tag_medium_low(self, node, container): self._map_tag(node, container, "tag_medium_low")
    def _handle_tag_low(self, node, container): self._map_tag(node, container, "tag_low")
    def _handle_tag_info(self, node, container): self._map_tag(node, container, "tag_info")
    def _handle_tag_success(self, node, container): self._map_tag(node, container, "tag_success")
    def _handle_tag_blue(self, node, container): self._map_tag(node, container, "tag_blue")
    def _handle_tag_light(self, node, container): self._map_tag_light(node, container)

    def _map_tag_light(self, node, container):
        """浅底深字标签：浅灰底 + 深灰字（对应 HTML .sr-tag--light）。
        作为单独段落渲染，前后留空格让标签块视觉上独立。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        p = container.add_paragraph()
        run = p.add_run(f" {text} ")
        run.bold = False
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor.from_string("1A1F36")
        self._set_run_shading(run, "EDF1F7")

    def _handle_muted_note(self, node, container):
        """图表注释/小字灰体段（对应 HTML .report-chart-note.sr-p.muted）：
        小字 + 浅灰色字 + 不加粗。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        p = container.add_paragraph()
        run = p.add_run(text)
        run.font.size = Pt(8.5)
        run.font.color.rgb = RGBColor.from_string("8A8F9A")

    def _handle_sub_paragraph(self, node, container):
        """子段落（对应 HTML .report-body.sr-p.sr-p--sub）：
        整段浅灰底 + 段前/段后留白，视觉与正文段落做区分。"""
        p = container.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        self._render_inline_with_br(p, node)
        if not p.runs:
            p._element.getparent().remove(p._element)
            return
        for run in p.runs:
            self._set_run_shading(run, "F5F7FA")

    def _handle_risk_card_head(self, node, container):
        """风险卡头部：把 sr-tag 和 sr-risk-card__title 拼到同一段落，
        单行带底色块呈现（对应 HTML header.sr-risk-card__head）。"""
        p = container.add_paragraph()
        for child in node.children:
            if isinstance(child, NavigableString):
                text = str(child).strip()
                if text:
                    p.add_run(text + " ")
            elif isinstance(child, Tag):
                classes = child.get("class") or []
                if child.name in ("h6", "h5", "h4", "h3", "h2", "h1") or "sr-risk-card__title" in classes:
                    title_text = child.get_text(" ", strip=True)
                    if title_text:
                        run = p.add_run(title_text)
                        run.bold = True
                elif "sr-tag--light" in classes:
                    # sr-tag--light 优先（同时带 --medium/--blue/--success 时也走 light 浅底深字样式）
                    text = child.get_text(" ", strip=True)
                    if text:
                        run = p.add_run(f" {text} ")
                        run.font.size = Pt(9)
                        run.font.color.rgb = RGBColor.from_string("1A1F36")
                        self._set_run_shading(run, "EDF1F7")
                elif any(c in ("sr-tag--success", "sr-tag--info", "sr-tag--blue",
                               "sr-tag--critical", "sr-tag--high", "sr-tag--medium",
                               "sr-tag--medium-low", "sr-tag--low") for c in classes):
                    # 用对应 tag handler 的颜色，作为 inline run 写入
                    tag_key = next((f"tag_{c.replace('sr-tag--', '')}" for c in classes
                                    if c.startswith("sr-tag--") and c != "sr-tag--light"), None)
                    text = child.get_text(" ", strip=True)
                    if text and tag_key:
                        bg, fg = _TAG_COLORS.get(tag_key, ("6F7785", "FFFFFF"))
                        run = p.add_run(f" {text} ")
                        run.bold = True
                        run.font.color.rgb = RGBColor.from_string(fg)
                        self._set_run_shading(run, bg)
                else:
                    text = child.get_text(" ", strip=True)
                    if text:
                        p.add_run(text + " ")

    def _handle_top5_asset_ip_row(self, node, container):
        """Top5 资产 IP 行：把 IP 和"未托管/已托管"标签拼到同一段落，
        标签渲染为灰色小字 + 括号包含（对应 HTML .sr-top5-asset-ip-row）。
        例：<div class="sr-top5-asset-ip-row"><span class="sr-top5-asset-ip">10.1.2.3</span><span class="sr-tag sr-tag--light sr-tag--medium">未托管</span></div>
        → Word: "10.1.2.3 (未托管)" 其中 "(未托管)" 是灰色 8.5pt 小字。"""
        p = container.add_paragraph()
        for child in node.children:
            if isinstance(child, NavigableString):
                text = str(child).strip()
                if text:
                    p.add_run(text + " ")
            elif isinstance(child, Tag):
                classes = child.get("class") or []
                if "sr-top5-asset-ip" in classes:
                    ip_text = child.get_text(" ", strip=True)
                    if ip_text:
                        ip_run = p.add_run(ip_text)
                        ip_run.bold = True
                elif any(c.startswith("sr-tag") for c in classes):
                    tag_text = child.get_text(" ", strip=True)
                    if tag_text:
                        # 灰色小字 + 括号
                        tag_run = p.add_run(f" ({tag_text})")
                        tag_run.font.size = Pt(8.5)
                        tag_run.font.color.rgb = RGBColor.from_string("8A8F9A")
                else:
                    text = child.get_text(" ", strip=True)
                    if text:
                        p.add_run(text + " ")

    def _handle_grade_badge(self, node, container):
        """评级徽章：居中加粗。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        p = container.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(text)
        run.bold = True
        run.font.size = Pt(16)

    def _map_tag(self, node, container, tag_key):
        """风险标签：红/橙/黄底色 + 白字 run。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        bg, fg = _TAG_COLORS.get(tag_key, ("6F7785", "FFFFFF"))
        p = container.add_paragraph()
        run = p.add_run(f" {text} ")
        run.bold = True
        run.font.color.rgb = RGBColor.from_string(fg)
        self._set_run_shading(run, bg)

    def _map_heading(self, node, container, level=1):
        text = node.get_text(" ", strip=True)
        if not text:
            return
        p = container.add_heading(text, level=level)
        # 兜底：清掉该段落的 numPr，避免 Word 自动加序号叠加成 "1. 1. xxx"
        self._strip_paragraph_num_pr(p)

    def _map_paragraph(self, node, container):
        # 段落内部可能包含 <br> / 块级标签 / 行内标签，需要按 <br> 拆段，
        # 与表格单元格 _render_cell_text_with_br 保持一致。
        p = container.add_paragraph()
        self._render_inline_with_br(p, node)
        # 解析 inline style 中的 text-indent:Nem，设 Word 首行缩进
        self._apply_text_indent(node, p, container)
        if not p.runs:
            # 没有任何 run 说明未写入内容，移除该空段
            p._element.getparent().remove(p._element)
        else:
            # 普通段落也可能继承到 List Number 样式导致自动编号，兜底清掉
            self._strip_paragraph_num_pr(p)

    def _apply_text_indent(self, node, paragraph, container):
        """从 node 的 style="text-indent:Nem" 解析首行缩进，1em 近似按当前字号 10.5pt 计算。"""
        style = node.get("style") if isinstance(node, Tag) else None
        if not style:
            return
        m = re.search(r"text-indent\s*:\s*([\d.]+)\s*em", style)
        if not m:
            return
        em = float(m.group(1))
        # 取当前正文字号作为 1em 的磅值
        size_pt = 10.5
        fonts_cfg = getattr(container, "fonts", {}) or {}
        normal_cfg = fonts_cfg.get("normal") if isinstance(fonts_cfg, dict) else None
        if isinstance(normal_cfg, dict) and normal_cfg.get("size_pt"):
            try:
                size_pt = float(normal_cfg["size_pt"])
            except (TypeError, ValueError):
                pass
        paragraph.paragraph_format.first_line_indent = Pt(em * size_pt)

    def _apply_run_fmt(self, run, fmt):
        """根据 fmt 描述给 run 应用 bold/italic/color。
        fmt 可为 None、字符串 "bold"/"italic" 或 dict {"bold","italic","color"}。"""
        if fmt is None:
            return
        if isinstance(fmt, str):
            if fmt == "bold":
                run.bold = True
            elif fmt == "italic":
                run.italic = True
            return
        if isinstance(fmt, dict):
            if fmt.get("bold"):
                run.bold = True
            if fmt.get("italic"):
                run.italic = True
            color = fmt.get("color")
            if color:
                try:
                    run.font.color.rgb = RGBColor.from_string(color)
                except Exception:
                    pass

    def _render_grade_badge_inline(self, paragraph, node):
        """将 <span class="sr-grade sr-grade--良">良</span> 作为 inline run 渲染：
        浅底色 + 深色字 + 9pt 加粗，左右留空格模拟徽章 padding。"""
        text = node.get_text(" ", strip=True)
        if not text:
            return
        classes = node.get("class", []) or []
        if isinstance(classes, str):
            classes = classes.split()
        grade_key = next((c for c in classes if c.startswith("sr-grade--")), None)
        bg, fg = _GRADE_COLORS.get(grade_key, _GRADE_DEFAULT)
        # 徽章前后留一个空格模拟 HTML 的 padding:2px 10px
        run = paragraph.add_run(f" {text} ")
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor.from_string(fg)
        self._set_run_shading(run, bg)

    def _render_inline_with_br(self, paragraph, node):
        """把 node 子节点按 <br> / 块级标签拆分写入段落，<br> 映射为软换行。
        <strong>/<b> → 加粗；<em>/<i> → 斜体；语义保留到独立 run。"""
        block_tags = {"div", "p"}
        bold_tags = {"strong", "b"}
        italic_tags = {"em", "i"}
        parts = []
        current_text = []
        children = list(node.children)
        for i, child in enumerate(children):
            if isinstance(child, Tag) and child.name == "br":
                parts.append(("text", "".join(current_text), None))
                parts.append(("br", None, None))
                current_text = []
            elif isinstance(child, Tag) and child.name in block_tags:
                parts.append(("text", "".join(current_text), None))
                parts.append(("text", child.get_text(" ", strip=True), None))
                if i < len(children) - 1:
                    parts.append(("br", None, None))
                current_text = []
            elif isinstance(child, NavigableString):
                current_text.append(str(child))
            elif isinstance(child, Tag) and child.name in bold_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), None))
                    current_text = []
                parts.append(("text", child.get_text(" ", strip=True), "bold"))
            elif isinstance(child, Tag) and child.name in italic_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), None))
                    current_text = []
                parts.append(("text", child.get_text(" ", strip=True), "italic"))
            elif isinstance(child, Tag):
                # 评级徽章 sr-grade：作为带底色 inline run 渲染到同一段落
                child_classes = child.get("class", []) or []
                if isinstance(child_classes, str):
                    child_classes = child_classes.split()
                if any(c == "sr-grade" or c.startswith("sr-grade--") for c in child_classes):
                    if current_text:
                        parts.append(("text", "".join(current_text), None))
                        current_text = []
                    parts.append(("grade_badge", child, None))
                else:
                    # 其他 span/容器标签：递归提取，保留嵌套 strong/b/em/i 的 bold/italic 语义
                    self._collect_inline_parts(child, current_text, parts, None)
        if current_text:
            parts.append(("text", "".join(current_text), None))
        for ptype, content, fmt in parts:
            if ptype == "text":
                text = (content or "").strip()
                if text:
                    run = paragraph.add_run(text)
                    self._apply_run_fmt(run, fmt)
            elif ptype == "br":
                run = paragraph.add_run()
                run.add_break()
            elif ptype == "grade_badge":
                self._render_grade_badge_inline(paragraph, content)

    def _collect_inline_parts(self, node, current_text, parts, inherited_fmt):
        """递归收集 node 子节点的 inline 文本，保留嵌套的 strong/b/em/i 与 color 语义。

        - 遇到 NavigableString 追加到 current_text
        - 遇到 strong/b：先 flush 当前累计文本，再开新 bold 文本段
        - 遇到 em/i：同上但 fmt=italic
        - 遇到 sr-text-danger span：以 {color: "CF171D"} 作为 inherited_fmt 递归子节点
        - 遇到其他 Tag：递归子节点（fmt 不变）

        inherited_fmt 可为 None 或 dict {"bold": bool, "italic": bool, "color": str}。
        非 None 时，bold/italic 会作用于该子树下的普通文本与 strong/em 文本，
        color 也会传播到这些 run。"""
        bold_tags = {"strong", "b"}
        italic_tags = {"em", "i"}
        # 若 node 自身就是 sr-text-danger 容器，先把已累计文本用外层 fmt flush，
        # 再以新 color 注入 inherited_fmt，避免外层文本被错误染红
        if isinstance(node, Tag):
            node_classes = node.get("class", []) or []
            if isinstance(node_classes, str):
                node_classes = node_classes.split()
            if "sr-text-danger" in node_classes:
                if current_text:
                    parts.append(("text", "".join(current_text), inherited_fmt))
                    current_text.clear()
                new_fmt = {"color": "CF171D"}
                if isinstance(inherited_fmt, dict):
                    if inherited_fmt.get("bold"):
                        new_fmt["bold"] = True
                    if inherited_fmt.get("italic"):
                        new_fmt["italic"] = True
                inherited_fmt = new_fmt
        for child in node.children:
            if isinstance(child, NavigableString):
                current_text.append(str(child))
            elif isinstance(child, Tag) and child.name in bold_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), inherited_fmt))
                    current_text.clear()
                fmt = {"bold": True}
                if isinstance(inherited_fmt, dict):
                    if inherited_fmt.get("italic"):
                        fmt["italic"] = True
                    if inherited_fmt.get("color"):
                        fmt["color"] = inherited_fmt["color"]
                parts.append(("text", child.get_text(" ", strip=True), fmt))
            elif isinstance(child, Tag) and child.name in italic_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), inherited_fmt))
                    current_text.clear()
                fmt = {"italic": True}
                if isinstance(inherited_fmt, dict):
                    if inherited_fmt.get("bold"):
                        fmt["bold"] = True
                    if inherited_fmt.get("color"):
                        fmt["color"] = inherited_fmt["color"]
                parts.append(("text", child.get_text(" ", strip=True), fmt))
            elif isinstance(child, Tag):
                child_classes = child.get("class", []) or []
                if isinstance(child_classes, str):
                    child_classes = child_classes.split()
                if "sr-text-danger" in child_classes:
                    # 红色字体容器：先把已累计文本用外层 fmt flush，再以新 color 递归子节点
                    if current_text:
                        parts.append(("text", "".join(current_text), inherited_fmt))
                        current_text.clear()
                    new_fmt = {"color": "CF171D"}
                    if isinstance(inherited_fmt, dict):
                        if inherited_fmt.get("bold"):
                            new_fmt["bold"] = True
                        if inherited_fmt.get("italic"):
                            new_fmt["italic"] = True
                    self._collect_inline_parts(child, current_text, parts, new_fmt)
                else:
                    self._collect_inline_parts(child, current_text, parts, inherited_fmt)

    def _map_list(self, node, container, ordered=False):
        for li in node.find_all("li", recursive=False):
            # 若 <li> 自带手写序号（如 sr-risk-step__num / sr-risk-step），
            # 跳过 Word 自动编号样式。把"手写序号 + 标题"作为单独段落，再
            # 递归处理内层嵌套 <ul>/<ol>，避免 get_text 把整棵子树拍平成一段。
            li_classes = li.get("class") or []
            has_handwritten_num = (
                "sr-risk-step" in li_classes
                or li.find(class_="sr-risk-step__num") is not None
            )
            if has_handwritten_num:
                self._map_risk_step(li, container)
                continue
            text = li.get_text(" ", strip=True)
            if not text:
                continue
            style = "List Number" if ordered else "List Bullet"
            container.add_paragraph(text, style=style)

    def _map_risk_step(self, li, container):
        """渲染 sr-risk-step：手写序号 + 标题段 + 嵌套列表段落。

        HTML 结构：
          <li class="sr-risk-step">
            <span class="sr-risk-step__num">1</span>
            <div class="sr-risk-step__content">
              <p class="sr-risk-step__title">网络防护</p>
              <ul class="sr-risk-step__list">
                <li>开启防火墙云情报网关订阅</li>
                ...
              </ul>
            </div>
          </li>
        生成：
          - 加粗段落"1 网络防护"（无 Word 自动序号）
          - 嵌套 <ul> 各 <li> 作为 List Bullet 段落
        """
        num_span = li.find(class_="sr-risk-step__num")
        num_text = num_span.get_text(strip=True) if num_span else ""
        # 找标题
        title_tag = li.find(class_="sr-risk-step__title")
        title_text = title_tag.get_text(" ", strip=True) if title_tag else ""
        # 生成"序号 + 标题"加粗段
        head_text = f"{num_text} {title_text}".strip() if title_text else num_text
        if head_text:
            p = container.add_paragraph()
            run = p.add_run(head_text)
            run.bold = True
            self._strip_paragraph_num_pr(p)
        # 处理内层嵌套列表（sr-risk-step__list 下的 <ul>/<ol>）
        nested_lists = li.find_all(["ul", "ol"], recursive=True)
        # 排除被嵌套 sr-risk-step（不会有，因为 sr-risk-step 在 li 上）
        for nested in nested_lists:
            # 避免重复处理：只处理直接属于本 li 的、不被更深层 sr-risk-step 包裹的
            # 简化：用 recursive=True 找到所有，但跳过 nested 的子 ul/ol
            if nested.find_parent(class_="sr-risk-step") is not li:
                continue
            self._map_list(nested, container, ordered=(nested.name == "ol"))

    def _image_max_size(self):
        """计算页面可用宽高（mm），用于限制图片不超页。"""
        cfg = self.config["docx"]
        content_w = cfg.get("page_width_mm", 297) - 2 * cfg.get("margin_mm", 20)
        content_h = cfg.get("page_height_mm", 210) - 2 * cfg.get("margin_mm", 20)
        return content_w, content_h

    def _fit_image_size(self, img_source):
        """根据图片像素尺寸与 scale，计算 Mm(width) 与 Mm(height)，并按页面
        可用宽高做等比缩放，保证既不超宽也不超高。

        img_source 可为文件路径字符串或 BytesIO 流。返回 (width_emu, height_emu)
        或 (None, None) 表示无法读取尺寸时退回 None。
        """
        try:
            with Image.open(img_source) as im:
                px_w, px_h = im.size
        except Exception as e:
            _log(f"读取图片尺寸失败，按默认宽度处理: {e}", "WARNING")
            return None, None
        # PNG 截图 scale=2，实际显示 DPI 默认按 96 处理：1px ≈ 0.2645 mm
        # 用 px → mm 直接换算并让 python-docx 用 Mm 落地
        mm_w = px_w * 25.4 / 96.0
        mm_h = px_h * 25.4 / 96.0
        max_w_mm, max_h_mm = self._image_max_size()
        # 优先约束宽度，再判断高度是否超页
        width_mm = min(mm_w, max_w_mm)
        scale = width_mm / mm_w if mm_w > 0 else 1.0
        height_mm = mm_h * scale
        # 若高度仍超页，按高度再缩一次
        if height_mm > max_h_mm:
            height_mm = max_h_mm
            scale = height_mm / mm_h if mm_h > 0 else 1.0
            width_mm = mm_w * scale
        return Mm(width_mm), Mm(height_mm)

    def _map_image(self, node, container):
        """处理 base64 data:image 与截图占位。"""
        snap = node.get("data-snapshot")
        if snap and snap in self._snapshot_map:
            img_path = self._snapshot_map[snap]
            if not os.path.exists(img_path):
                _log(f"截图文件不存在（忽略）: {img_path}", "WARNING")
                return
            w, h = self._fit_image_size(img_path)
            if w is None or h is None:
                content_w = self.config["docx"]["page_width_mm"] - 2 * self.config["docx"]["margin_mm"]
                container.add_picture(img_path, width=Mm(content_w))
            else:
                container.add_picture(img_path, width=w, height=h)
            return
        src = node.get("src") or ""
        if src.startswith("data:image/"):
            head, b64 = src.split(",", 1) if "," in src else ("", src)
            try:
                raw = base64.b64decode(b64)
                stream = io.BytesIO(raw)
                w, h = self._fit_image_size(stream)
                stream.seek(0)
                if w is None or h is None:
                    container.add_picture(stream, width=Mm(80))
                else:
                    container.add_picture(stream, width=w, height=h)
            except Exception as e:
                _log(f"base64 图片解码失败（忽略）: {e}", "WARNING")
            return
        if src:
            try:
                if src.startswith("file://"):
                    img_path = src[7:].lstrip("/")
                else:
                    img_path = str((self.input_path.parent / src).resolve())
                if os.path.exists(img_path):
                    w, h = self._fit_image_size(img_path)
                    if w is None or h is None:
                        container.add_picture(img_path, width=Mm(80))
                    else:
                        container.add_picture(img_path, width=w, height=h)
            except Exception as e:
                _log(f"外部图片加载失败（忽略）: {src} ({e})", "WARNING")

    def _map_table(self, node, container):
        """映射 HTML table 到 docx table，处理 colspan/rowspan 以及 <br> 换行。"""
        rows = node.find_all("tr", recursive=True)
        if not rows:
            return
        # 文档信息表（sr-copyright-meta）单独设垂直居中，其他表保持默认顶部对齐
        node_classes = node.get("class") or []
        is_doc_info_table = "sr-copyright-meta" in node_classes
        max_cols = 0
        grid = []
        has_any_th = False
        for tr in rows:
            cells = tr.find_all(["td", "th"], recursive=False)
            col_sum = 0
            row_data = []
            for c in cells:
                try:
                    colspan = int(c.get("colspan", 1) or 1)
                except (ValueError, TypeError):
                    colspan = 1
                try:
                    rowspan = int(c.get("rowspan", 1) or 1)
                except (ValueError, TypeError):
                    rowspan = 1
                if c.name == "th":
                    has_any_th = True
                row_data.append((c, colspan, rowspan))
                col_sum += colspan
            max_cols = max(max_cols, col_sum)
            grid.append(row_data)
        if max_cols == 0:
            return
        table = container.add_table(rows=len(grid), cols=max_cols)
        occupied = {}
        for ri, row_data in enumerate(grid):
            ci = 0
            is_header_row = (ri == 0 and not has_any_th) or all(
                soup.name == "th" for soup, _, _ in row_data
            )
            for cell_soup, colspan, rowspan in row_data:
                while (ri, ci) in occupied:
                    ci += 1
                cell = table.cell(ri, ci)
                self._render_cell_text_with_br(cell, cell_soup)
                # 文档信息表单元格垂直居中（水平保持左对齐）
                if is_doc_info_table:
                    try:
                        from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
                        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
                    except Exception as e:
                        _log(f"设置单元格垂直居中失败: {e}", "WARNING")
                if colspan > 1:
                    for k in range(1, colspan):
                        try:
                            merged = cell.merge(table.cell(ri, ci + k))
                            cell = merged
                        except Exception:
                            pass
                if rowspan > 1:
                    for r in range(1, rowspan):
                        for k in range(colspan):
                            occupied[(ri + r, ci + k)] = True
                if is_header_row or cell_soup.name == "th":
                    self._apply_table_header_cell_style(cell)
                ci += colspan
        self._set_table_column_widths_by_grid(table, grid)
        self._set_table_borders(table)

    # 表头样式：浅蓝底（#EDF1F7）+ 深色字（#1A1F36），与 HTML .sr-tbl th 保持一致
    _TABLE_HEADER_BG = "EDF1F7"
    _TABLE_HEADER_FG = "1A1F36"

    def _apply_table_header_cell_style(self, cell):
        """给表头单元格应用浅蓝底 + 黑字样式（对齐 HTML .sr-tbl th 视觉）。"""
        self._set_cell_shading(cell, self._TABLE_HEADER_BG)
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.color.rgb = RGBColor.from_string(self._TABLE_HEADER_FG)
                run.bold = True

    def _set_cell_shading(self, cell, hex_color):
        """给单元格设置底色（w:shd 写入 tcPr）。"""
        tcPr = cell._tc.get_or_add_tcPr()
        old = tcPr.find(qn("w:shd"))
        if old is not None:
            tcPr.remove(old)
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        tcPr.append(shd)

    def _set_table_column_widths_by_grid(self, table, grid):
        """根据全表所有行计算列宽并固定到 Word 表格。

        旧 _set_table_column_widths_by_header 只用 grid[0] 算权重，遇到首行列数
        < max_cols 的表（如文档信息表：首行 2 列、中间行 4 列），zip 会截断，
        剩下列宽度未设导致 Word 按内容撑开溢出。
        本函数扫全 grid，按 colspan 展开到 max_cols 槽位，对每列取该列出现过的
        最大权重，统一归一化到内容宽度。

        策略：
          - 中文字符按 2 宽度权重，英文/数字按 1 宽度
          - 每列权重 = 该列在所有行出现过的单元格权重的最大值
          - 按权重比例分配页面内容宽度（page_width - 2 * margin）
          - 最小列宽 10mm，避免空列宽为 0
          - 关闭 autofit + 设置 tblLayout=fixed，确保 Word 按指定列宽渲染

        Args:
            table: docx Table 对象
            grid: 全表行数据 [[(cell_soup, colspan, rowspan), ...], ...]，
                  与 _map_table 中 grid 一致
        """
        if not grid:
            return
        max_cols = 0
        for row_data in grid:
            cols = sum(int(cs or 1) for _, cs, _ in row_data)
            max_cols = max(max_cols, cols)
        if max_cols == 0:
            return
        cfg = self.config.get("docx", {})
        page_w_mm = cfg.get("page_width_mm", 210)
        margin_mm = cfg.get("margin_mm", 20)
        content_w_mm = page_w_mm - 2 * margin_mm
        min_col_mm = 10

        # 扫全 grid，按 colspan 展开到 max_cols 槽位，每列取出现过的最大权重
        col_weights = [0.0] * max_cols
        for row_data in grid:
            ci = 0
            for cell_soup, colspan, rowspan in row_data:
                n = max(int(colspan or 1), 1)
                if cell_soup is None:
                    weight = 0.0
                else:
                    text = cell_soup.get_text(strip=True) or ""
                    # 中文字符（ord > 127）按 2 宽度，其他按 1
                    weight = sum(2 if ord(c) > 127 else 1 for c in text)
                # 单元格权重按 colspan 平摊到每个槽位
                each_w = weight / n
                for k in range(n):
                    if ci + k < max_cols and each_w > col_weights[ci + k]:
                        col_weights[ci + k] = each_w
                ci += n
        # 空列兜底权重 1.0，避免后续归一时除 0 或被忽略
        col_weights = [max(w, 1.0) for w in col_weights]

        # 列数过多退化到平均分配；否则按权重比例分配并兜底最小列宽
        if min_col_mm * max_cols >= content_w_mm:
            each = content_w_mm / max_cols
            col_widths_mm = [each] * max_cols
        else:
            total_weight = sum(col_weights)
            col_widths_mm = [content_w_mm * w / total_weight for w in col_weights]
            col_widths_mm = [max(w, min_col_mm) for w in col_widths_mm]
            # 拉底后总宽可能超 content_w，按比例归一
            total = sum(col_widths_mm)
            if total > content_w_mm and total > 0:
                scale = content_w_mm / total
                col_widths_mm = [w * scale for w in col_widths_mm]

        # 关闭 autofit，设置 tblLayout=fixed
        table.autofit = False
        table.allow_autofit = False
        tbl = table._tbl
        tblPr = tbl.find(qn("w:tblPr"))
        if tblPr is None:
            tblPr = OxmlElement("w:tblPr")
            tbl.insert(0, tblPr)

        layout = tblPr.find(qn("w:tblLayout"))
        if layout is None:
            layout = OxmlElement("w:tblLayout")
            tblPr.append(layout)
        layout.set(qn("w:type"), "fixed")

        # tblW 总宽（dxa = twips）
        total_twips = int(round(content_w_mm * 1440 / 25.4))
        tblW = tblPr.find(qn("w:tblW"))
        if tblW is None:
            tblW = OxmlElement("w:tblW")
            tblPr.append(tblW)
        tblW.set(qn("w:type"), "dxa")
        tblW.set(qn("w:w"), str(total_twips))

        # 各 gridCol 宽度（twips）
        tblGrid = tbl.find(qn("w:tblGrid"))
        if tblGrid is None:
            return
        for gridCol, width_mm in zip(tblGrid.findall(qn("w:gridCol")), col_widths_mm):
            twips = int(round(width_mm * 1440 / 25.4))
            gridCol.set(qn("w:w"), str(twips))

    def _set_table_column_widths_by_header(self, table, header_row):
        """根据表头单元格文本长度计算列宽并固定到 Word 表格。

        策略：
          - 中文字符按 2 宽度权重，英文/数字按 1 宽度
          - 按权重比例分配页面内容宽度（page_width - 2 * margin）
          - 最小列宽 10mm，避免空表头列宽为 0
          - 关闭 autofit + 设置 tblLayout=fixed，确保 Word 按指定列宽渲染

        Args:
            table: docx Table 对象
            header_row: 表头行数据 [(cell_soup, colspan, rowspan), ...]，
                        与 _map_table 中 grid[0] 一致
        """
        if not header_row:
            return
        cfg = self.config.get("docx", {})
        page_w_mm = cfg.get("page_width_mm", 210)
        margin_mm = cfg.get("margin_mm", 20)
        content_w_mm = page_w_mm - 2 * margin_mm
        min_col_mm = 10

        # 按 colspan 展开，把表头权重铺到每个 gridCol 上
        col_weights = []
        for cell_soup, colspan, rowspan in header_row:
            text = cell_soup.get_text(strip=True) if cell_soup else ""
            # 中文字符（ord > 127）按 2 宽度，其他按 1
            weight = sum(2 if ord(c) > 127 else 1 for c in text)
            n = max(int(colspan or 1), 1)
            col_weights.extend([weight / n] * n)

        if not col_weights:
            return
        col_weights = [max(w, 1.0) for w in col_weights]

        # 列数过多退化到平均分配；否则按权重比例分配并兜底最小列宽
        if min_col_mm * len(col_weights) >= content_w_mm:
            each = content_w_mm / len(col_weights)
            col_widths_mm = [each] * len(col_weights)
        else:
            total_weight = sum(col_weights)
            col_widths_mm = [content_w_mm * w / total_weight for w in col_weights]
            col_widths_mm = [max(w, min_col_mm) for w in col_widths_mm]
            # 拉底后总宽可能超 content_w，按比例归一
            total = sum(col_widths_mm)
            if total > content_w_mm and total > 0:
                scale = content_w_mm / total
                col_widths_mm = [w * scale for w in col_widths_mm]

        # 关闭 autofit，设置 tblLayout=fixed
        table.autofit = False
        table.allow_autofit = False
        tbl = table._tbl
        tblPr = tbl.find(qn("w:tblPr"))
        if tblPr is None:
            tblPr = OxmlElement("w:tblPr")
            tbl.insert(0, tblPr)

        layout = tblPr.find(qn("w:tblLayout"))
        if layout is None:
            layout = OxmlElement("w:tblLayout")
            tblPr.append(layout)
        layout.set(qn("w:type"), "fixed")

        # tblW 总宽（dxa = twips）
        total_twips = int(round(content_w_mm * 1440 / 25.4))
        tblW = tblPr.find(qn("w:tblW"))
        if tblW is None:
            tblW = OxmlElement("w:tblW")
            tblPr.append(tblW)
        tblW.set(qn("w:type"), "dxa")
        tblW.set(qn("w:w"), str(total_twips))

        # 各 gridCol 宽度（twips）
        tblGrid = tbl.find(qn("w:tblGrid"))
        if tblGrid is None:
            return
        for gridCol, width_mm in zip(tblGrid.findall(qn("w:gridCol")), col_widths_mm):
            twips = int(round(width_mm * 1440 / 25.4))
            gridCol.set(qn("w:w"), str(twips))

    def _render_cell_text_with_br(self, cell, cell_soup):
        """将 HTML 单元格文本写入 docx cell，<br> 和块级标签（<div>、<p>）
        都映射为 Word 软换行。<strong>/<b> → 加粗；<em>/<i> → 斜体。"""
        block_tags = {"div", "p"}
        bold_tags = {"strong", "b"}
        italic_tags = {"em", "i"}
        parts = []
        current_text = []
        children = list(cell_soup.children)
        for i, child in enumerate(children):
            if isinstance(child, Tag) and child.name == "br":
                parts.append(("text", "".join(current_text), None))
                parts.append(("br", None, None))
                current_text = []
            elif isinstance(child, Tag) and child.name in block_tags:
                # 专门处理 sr-component-name-row：把组件名称和类型标签
                # 作为两个独立 run 渲染到同一段落，保留视觉区分
                classes = child.get("class", []) or []
                if isinstance(classes, str):
                    classes = classes.split()
                if "sr-component-name-row" in classes:
                    parts.append(("text", "".join(current_text), None))
                    parts.append(("component_name_row", child, None))
                    current_text = []
                    continue
                if "sr-top5-asset-ip-row" in classes:
                    # Top5 资产行：IP 加粗 + 托管状态灰色小字括号
                    parts.append(("text", "".join(current_text), None))
                    parts.append(("top5_asset_ip_row", child, None))
                    current_text = []
                    continue
                # 块级标签：先把累计文本 flush，再提取块文本
                parts.append(("text", "".join(current_text), None))
                parts.append(("text", child.get_text(" ", strip=True), None))
                # 仅当不是最后一个子元素时才加换行，避免末尾多一个空行
                if i < len(children) - 1:
                    parts.append(("br", None, None))
                current_text = []
            elif isinstance(child, NavigableString):
                current_text.append(str(child))
            elif isinstance(child, Tag) and child.name in bold_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), None))
                    current_text = []
                parts.append(("text", child.get_text(" ", strip=True), "bold"))
            elif isinstance(child, Tag) and child.name in italic_tags:
                if current_text:
                    parts.append(("text", "".join(current_text), None))
                    current_text = []
                parts.append(("text", child.get_text(" ", strip=True), "italic"))
            elif isinstance(child, Tag):
                # 识别 sr-tag--light 系列（浅底深字标签），单独 flush
                child_classes = child.get("class", []) or []
                if isinstance(child_classes, str):
                    child_classes = child_classes.split()
                if any(c == "sr-grade" or c.startswith("sr-grade--") for c in child_classes):
                    # 评级徽章：作为带底色 inline run
                    if current_text:
                        parts.append(("text", "".join(current_text), None))
                        current_text = []
                    parts.append(("grade_badge", child, None))
                elif "sr-tag--light" in child_classes:
                    if current_text:
                        parts.append(("text", "".join(current_text), None))
                        current_text = []
                    parts.append(("tag_light", child, None))
                elif any(c in ("sr-tag--success", "sr-tag--info", "sr-tag--blue",
                               "sr-tag--critical", "sr-tag--high", "sr-tag--medium",
                               "sr-tag--medium-low", "sr-tag--low") for c in child_classes):
                    # 深色 tag 系列：作为带底色 inline run
                    if current_text:
                        parts.append(("text", "".join(current_text), None))
                        current_text = []
                    parts.append(("tag_dark", child, None))
                else:
                    # 其他 span/容器标签：递归提取，保留嵌套 strong/b/em/i 的 bold/italic 语义
                    self._collect_inline_parts(child, current_text, parts, None)
        if current_text:
            parts.append(("text", "".join(current_text), None))
        # 写入 cell：使用段落+run 的标准方式，<br> 通过 run.add_break() 实现
        paragraph = cell.paragraphs[0]
        # 清空默认 run
        for r in list(paragraph.runs):
            r._element.getparent().remove(r._element)
        for ptype, content, fmt in parts:
            if ptype == "text":
                text = (content or "").strip()
                if text:
                    run = paragraph.add_run(text)
                    self._apply_run_fmt(run, fmt)
            elif ptype == "br":
                # 在新 run 中插入软换行（<w:br/>，必须在 <w:r> 内部）
                run = paragraph.add_run()
                run.add_break()
            elif ptype == "component_name_row":
                self._render_component_name_row(paragraph, content)
            elif ptype == "top5_asset_ip_row":
                self._render_top5_asset_ip_row(paragraph, content)
            elif ptype == "grade_badge":
                self._render_grade_badge_inline(paragraph, content)
            elif ptype == "tag_light":
                # 浅底深字标签：EDF1F7 底 + 1A1F36 字 + 9pt
                text = content.get_text(" ", strip=True)
                if text:
                    run = paragraph.add_run(f" {text} ")
                    run.font.size = Pt(9)
                    run.font.color.rgb = RGBColor.from_string("1A1F36")
                    self._set_run_shading(run, "EDF1F7")
            elif ptype == "tag_dark":
                # 深底白字标签：根据 sr-tag--xxx 取对应色
                classes = content.get("class", []) or []
                if isinstance(classes, str):
                    classes = classes.split()
                tag_key = next((f"tag_{c.replace('sr-tag--', '')}" for c in classes
                                if c.startswith("sr-tag--") and c != "sr-tag--light"), None)
                text = content.get_text(" ", strip=True)
                if text and tag_key:
                    bg, fg = _TAG_COLORS.get(tag_key, ("6F7785", "FFFFFF"))
                    run = paragraph.add_run(f" {text} ")
                    run.bold = True
                    run.font.color.rgb = RGBColor.from_string(fg)
                    self._set_run_shading(run, bg)

    def _render_component_name_row(self, paragraph, div_node):
        """渲染组件名称行：组件名称（默认字号、加粗、黑色）+ 类型（括号形式、灰色小字）
        作为两个独立 run 渲染到同一段落，保留视觉区分度。"""
        # 组件名称
        name_tag = div_node.find("span", class_="sr-component-name")
        if name_tag is not None:
            name_text = name_tag.get_text(strip=True)
            if name_text:
                name_run = paragraph.add_run(name_text)
                name_run.font.size = Pt(10.5)
                name_run.font.bold = True
                name_run.font.color.rgb = RGBColor(0x1F, 0x23, 0x2E)

        # 类型标签（sr-tag sr-tag--light sr-tag--blue）
        type_tag = None
        for span in div_node.find_all("span", class_="sr-tag"):
            classes = span.get("class", []) or []
            if isinstance(classes, str):
                classes = classes.split()
            if "sr-tag--blue" in classes or "sr-tag--light" in classes:
                type_tag = span
                break
        if type_tag is not None:
            type_text = type_tag.get_text(strip=True)
            if type_text:
                # 名称与类型之间留一个空格分隔，类型用括号形式、灰色小字
                paragraph.add_run(" ")
                type_run = paragraph.add_run(f"({type_text})")
                type_run.font.size = Pt(8)
                type_run.font.color.rgb = RGBColor(0x8A, 0x8F, 0x9A)

    def _render_top5_asset_ip_row(self, paragraph, div_node):
        """渲染 Top5 资产行：IP（默认字号、加粗、黑色）+ 托管状态（括号形式、灰色小字）
        作为两个独立 run 渲染到同一段落，与 _render_component_name_row 风格保持一致。

        HTML 结构：
        <div class="sr-top5-asset-ip-row">
          <span class="sr-top5-asset-ip">10.128.160.30</span>
          <span class="sr-tag sr-tag--light sr-tag--medium">未托管</span>
        </div>
        → Word: "10.128.160.30 (未托管)" 其中 "(未托管)" 是 8pt 灰色小字。"""
        # IP
        ip_tag = div_node.find("span", class_="sr-top5-asset-ip")
        if ip_tag is not None:
            ip_text = ip_tag.get_text(strip=True)
            if ip_text:
                ip_run = paragraph.add_run(ip_text)
                ip_run.font.size = Pt(10.5)
                ip_run.font.bold = True
                ip_run.font.color.rgb = RGBColor(0x1F, 0x23, 0x2E)

        # 托管状态标签（sr-tag--light 系列）
        status_tag = None
        for span in div_node.find_all("span", class_="sr-tag"):
            classes = span.get("class", []) or []
            if isinstance(classes, str):
                classes = classes.split()
            if any(c.startswith("sr-tag--") for c in classes):
                status_tag = span
                break
        if status_tag is not None:
            status_text = status_tag.get_text(strip=True)
            if status_text:
                # IP 与状态之间留一个空格分隔，状态用括号形式、灰色小字
                paragraph.add_run(" ")
                status_run = paragraph.add_run(f"({status_text})")
                status_run.font.size = Pt(8)
                status_run.font.color.rgb = RGBColor(0x8A, 0x8F, 0x9A)

    # ── 工具：shading / borders ─────────────────────

    def _set_table_borders(self, table):
        """给表格加细边框。"""
        tbl = table._tbl
        tblPr = tbl.find(qn("w:tblPr"))
        if tblPr is None:
            tblPr = OxmlElement("w:tblPr")
            tbl.insert(0, tblPr)
        borders = OxmlElement("w:tblBorders")
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            b = OxmlElement(f"w:{edge}")
            b.set(qn("w:val"), "single")
            b.set(qn("w:sz"), "4")
            b.set(qn("w:color"), "D3D7DE")
            borders.append(b)
        old = tblPr.find(qn("w:tblBorders"))
        if old is not None:
            tblPr.remove(old)
        tblPr.append(borders)

    def _set_run_shading(self, run, hex_color):
        """给 run 设置底色。"""
        rPr = run._element.get_or_add_rPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        rPr.append(shd)

    # ──────────────────────────────────────────────
    # 编排
    # ──────────────────────────────────────────────

    def run(self):
        """编排：load_config → render_html → snapshot → extract_dom → assemble_docx。"""
        try:
            self.load_config()
            page = self.render_html()
            snapshot_map = self.snapshot_complex_components(page)
            root = self.extract_dom(page)
            self.assemble_docx(root, snapshot_map, self.output_path)
            _log(f"转换完成: {self.output_path}")
        finally:
            self.close()


def main():
    parser = argparse.ArgumentParser(
        description="通用 HTML → Word 转换（混合保真：文本结构化 + 复杂组件截图）"
    )
    parser.add_argument("--input", "-i", default="客户_start_end_安全体检报告.html", help="输入 HTML 文件路径")
    parser.add_argument("--output", "-o", default=None, help="输出 docx 路径（默认 tmp/<输入名>.docx）")
    parser.add_argument("--config", "-c", default=None, help="配置文件 YAML 路径")
    parser.add_argument("--preview-mode", default=None,
                        choices=["a4-landscape", "a4-portrait", "html"],
                        help="覆盖配置中的 preview_mode")
    args = parser.parse_args()
    exporter = HtmlToWordExporter(
        input_path=args.input,
        output_path=args.output,
        config_path=args.config,
        preview_mode=args.preview_mode,
    )
    exporter.run()


if __name__ == "__main__":
    main()
