// Hide flash messages after a few seconds
document.addEventListener('DOMContentLoaded', function(){
  setTimeout(function(){
    document.querySelectorAll('.alert').forEach(function(el){
      el.style.transition = 'opacity 0.6s';
      el.style.opacity = '0';
    });
  }, 4500);
});
