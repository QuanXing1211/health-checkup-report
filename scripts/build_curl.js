const fs = require('fs');
const col = JSON.parse(fs.readFileSync('postman_collection.json', 'utf8'));
const req = col.item[0].request;
const url = req.url.raw;
const body = req.body.raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

let lines = [];
lines.push('curl -X POST "' + url + '"');

for (const h of req.header) {
    if (h.key === 'Cookie') continue; // put Cookie last
    const v = h.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    lines.push('  -H "' + h.key + ': ' + v + '"');
}

const cookieH = req.header.find(h => h.key === 'Cookie');
const cookieV = cookieH.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
lines.push('  -H "Cookie: ' + cookieV + '"');
lines.push('  -d "' + body + '"');

fs.writeFileSync('postman_curl_inline.sh', lines.join(' \\\n'));
console.log('Done: postman_curl_inline.sh');
console.log('Line count:', lines.length);
