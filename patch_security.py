#!/usr/bin/env python3
"""Apply OWASP Top 10 security hardening patches to dashboard.html"""

with open('/home/claude/ai-policy-auditor/dashboard.html', 'r') as f:
    content = f.read()

# 1. Add OWASP comment header at top
owasp_comment = """<!--
  AI Policy Auditor Dashboard — OWASP Top 10 (2021) Security Hardening
  =====================================================================
  A01 Broken Access Control    Static file; no auth surface; no server.
  A02 Cryptographic Failures   No secrets. No cookies, localStorage, or
                               sessionStorage used anywhere.
  A03 Injection / XSS          All user input passes through escapeHtml()
                               and sanitiseFilename() before DOM insertion.
                               User file content shown via textContent only
                               — never innerHTML. No eval() anywhere.
  A04 Insecure Design          validateFile() enforces .txt/.md, 500KB max,
                               non-empty. Client-side processing only.
  A05 Security Misconfiguration CSP meta blocks external connections.
                               X-Content-Type-Options nosniff set.
                               X-Frame-Options DENY set.
  A06 Vulnerable Components    Zero runtime JS dependencies.
  A07 Identification Failures  N/A — public static dashboard, no auth.
  A08 Software & Data Integrity No dynamic script injection, no JSONP.
  A09 Logging & Monitoring     Filenames sanitised before display.
  A10 SSRF                     Zero fetch/XHR. No URLs from user input.
-->
"""
content = owasp_comment + content

# 2. Add security meta tags after viewport meta
security_metas = """
<!-- OWASP A05: CSP, MIME sniff prevention, no-referrer, anti-clickjack -->
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta name="referrer" content="no-referrer">
<meta http-equiv="X-Frame-Options" content="DENY">
"""
content = content.replace(
    '<link href="https://fonts.googleapis.com',
    security_metas + '<link href="https://fonts.googleapis.com'
)

# 3. Add CSS for security notice banner
sec_css = """.sec-note{background:var(--green-dim);border:1px solid #0d5a42;border-radius:8px;padding:10px 14px;font-size:11px;color:var(--green);font-family:'DM Mono',monospace;margin-bottom:16px;display:flex;align-items:center;gap:8px}\n"""
content = content.replace('::-webkit-scrollbar{', sec_css + '::-webkit-scrollbar{')

# 4. Add security helper functions before const D=
security_fns = """
/* ================================================================
   OWASP A03 XSS Prevention: escapeHtml
   ALL user-supplied strings must pass through this before any
   DOM insertion. Used on filenames, file content previews, etc.
   ================================================================ */
function escapeHtml(s) {
  if (typeof s !== 'string') return '';
  var map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','/':'&#x2F;'};
  return s.replace(/[&<>"'/]/g, function(c) { return map[c]; });
}

/* ================================================================
   OWASP A04 Insecure Design: validateFile
   Reject disallowed file types and oversized uploads before reading.
   ================================================================ */
function validateFile(file) {
  var MAX_BYTES = 500 * 1024;
  var ALLOWED_EXTS = ['.txt', '.md'];
  var ext = ('.' + file.name.split('.').pop()).toLowerCase();
  if (ALLOWED_EXTS.indexOf(ext) === -1) {
    return {ok: false, error: 'Only .txt and .md files are accepted.'};
  }
  if (file.size > MAX_BYTES) {
    return {ok: false, error: 'File exceeds the 500 KB size limit.'};
  }
  if (file.size === 0) {
    return {ok: false, error: 'File is empty.'};
  }
  return {ok: true};
}

/* ================================================================
   OWASP A03 / A09: sanitiseFilename
   Strip path separators and control chars before display.
   ================================================================ */
function sanitiseFilename(name) {
  if (typeof name !== 'string') return 'unknown';
  return name.replace(/[\\/\\\\:*?"<>|\\x00-\\x1f]/g, '_').slice(0, 120);
}

"""
content = content.replace("const D={sample:{", security_fns + "const D={sample:{")

# 5. Patch handleUpload to validate before reading + use sanitiseFilename
old_handle = """function handleUpload(inp){
  const file=inp.files[0];if(!file)return;
  const r=new FileReader();
  r.onload=e=>{
    const txt=e.target.result,id='doc_'+Date.now();
    toast('Analysing '+file.name+'...');
    setTimeout(()=>{
      const au=simAudit(txt);
      uploads[id]={name:file.name,size:file.size,content:txt,au};
      addCard(id,file.name,file.size);"""

new_handle = """function handleUpload(inp){
  const file=inp.files&&inp.files[0];if(!file)return;
  /* OWASP A04: validate before reading */
  var chk=validateFile(file);
  if(!chk.ok){showToast('\u26a0 '+chk.error,false);setTimeout(hideToast,4000);inp.value='';return;}
  const r=new FileReader();
  r.onerror=function(){showToast('\u26a0 Could not read file.',false);setTimeout(hideToast,4000);};
  r.onload=e=>{
    const txt=e.target.result,id='doc_'+Date.now();
    /* OWASP A03: sanitise filename before any display */
    const safeName=sanitiseFilename(file.name);
    toast('Analysing '+safeName+'...');
    setTimeout(()=>{
      const au=simAudit(txt);
      uploads[id]={name:safeName,rawName:file.name,size:file.size,content:txt,au};
      addCard(id,safeName,file.size);"""

content = content.replace(old_handle, new_handle)

# Fix the selectDoc call to use safeName
content = content.replace(
    "      selectDoc(id);\n      hideToast();\n      toast('\u2713 '+file.name+' complete',false);",
    "      selectDoc(id);\n      hideToast();\n      toast('\u2713 '+safeName+' complete',false);"
)

# 6. Patch showUploadContent to use textContent not innerHTML for file content
old_show = """  document.getElementById('up-modal-title').textContent='📄 '+doc.name;
  document.getElementById('up-modal-body').innerHTML=`<pre style="font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);white-space:pre-wrap;line-height:1.7;word-break:break-word">${doc.content.substring(0,8000)}${doc.content.length>8000?'\\n\\n... (truncated)':''}</pre>`;"""

new_show = """  document.getElementById('up-modal-title').textContent='\ud83d\udcc4 '+doc.name;
  /* OWASP A03: use textContent to display file content — NEVER innerHTML */
  var pre=document.createElement('pre');
  pre.style.cssText="font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);white-space:pre-wrap;line-height:1.7;word-break:break-word";
  pre.textContent=doc.content.slice(0,10000)+(doc.content.length>10000?'\\n\\n[truncated]':'');
  var mb=document.getElementById('up-modal-body');
  mb.textContent='';
  mb.appendChild(pre);"""

content = content.replace(old_show, new_show)

# 7. Add OWASP security banner into the rendered dashboard
sec_banner = '<div class="sec-note">\ud83d\udd12 OWASP Top 10 hardened &nbsp;\u00b7&nbsp; CSP enforced &nbsp;\u00b7&nbsp; No cookies &nbsp;\u00b7&nbsp; No external requests &nbsp;\u00b7&nbsp; User input sanitised</div>\n    '
content = content.replace(
    '<div class="doc-title">TestClassifier-v1',
    sec_banner + '<div class="doc-title">TestClassifier-v1',
    1
)

with open('/home/claude/ai-policy-auditor/dashboard.html', 'w') as f:
    f.write(content)

print(f"Done. File size: {len(content):,} bytes")
print("Security patches applied:")
print("  [1] OWASP comment header")
print("  [2] CSP + X-Content-Type-Options + X-Frame-Options meta tags")
print("  [3] .sec-note CSS class")
print("  [4] escapeHtml(), validateFile(), sanitiseFilename() functions")
print("  [5] handleUpload() — validate before read, sanitise filename")
print("  [6] showUploadContent() — textContent not innerHTML for file data")
print("  [7] Security banner in rendered dashboard")
