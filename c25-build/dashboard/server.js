const express = require('express');
const { exec } = require('child_process');
const app = express();
function run(cmd) { return new Promise(r => exec(cmd, {timeout:2000}, (e,o)=>r(e?'0':(o||'0').trim()))); }
app.get('/api', async (req, res) => {
  try {
    const cpu = await run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'.' -f1 || echo 0");
    const mem = await run("awk '/MemAvailable/{a=$2}/MemTotal/{t=$2}END{if(t>0) print int((t-a)/t*100); else print 0}' /proc/meminfo || echo 0");
    res.json({cpu:parseInt(cpu)||0, mem:parseInt(mem)||0});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.use(express.static(__dirname));
app.listen(8080, () => console.log('C25 Dashboard Live: http://localhost:8080'));
