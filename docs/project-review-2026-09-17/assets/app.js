// تقرير المراجعة — تفاعلات خفيفة بدون مكتبات خارجية
(function(){
  function ring(id, pct){
    var el = document.getElementById(id);
    if(!el) return;
    var c = 2*Math.PI*64;
    var fg = el.querySelector('.fg');
    if(fg){
      fg.style.strokeDasharray = c;
      fg.style.strokeDashoffset = (c*(1-pct/100)).toFixed(1);
    }
    var t = el.querySelector('.pct');
    if(t) t.textContent = pct + '%';
  }
  document.addEventListener('DOMContentLoaded', function(){
    ring('scoreRing', 82);
    ring('secRing', 78);
    ring('qualRing', 86);
    ring('testRing', 94);
    // فلترة جدول المخاطر
    var q = document.getElementById('riskFilter');
    if(q){
      q.addEventListener('input', function(){
        var v = q.value.trim();
        document.querySelectorAll('#riskTable tbody tr').forEach(function(tr){
          tr.style.display = !v || tr.textContent.indexOf(v) !== -1 ? '' : 'none';
        });
      });
    }
    // نسخ الأمر
    document.querySelectorAll('[data-copy]').forEach(function(b){
      b.addEventListener('click', function(){
        var t = b.getAttribute('data-copy');
        if(navigator.clipboard) navigator.clipboard.writeText(t);
        b.textContent = 'تم النسخ ✓';
        setTimeout(function(){ b.textContent = 'نسخ الأمر'; }, 1500);
      });
    });
    // سنة التقرير
    var y = document.getElementById('year'); if(y) y.textContent = new Date().getFullYear();
  });
})();
