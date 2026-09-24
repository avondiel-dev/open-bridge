/* On narrow screens the site links sit in a row that scrolls sideways
   (brand.css). Bring the current page's link into view once, without moving
   the page itself: scrollLeft on the row, never scrollIntoView. */
(function(){
  var nav = document.querySelector(".site-nav");
  var cur = nav && nav.querySelector('[aria-current="page"]');
  if(!cur || nav.scrollWidth <= nav.clientWidth) return;
  var left = cur.offsetLeft - (nav.clientWidth - cur.offsetWidth) / 2;
  nav.scrollLeft = Math.max(0, left - nav.offsetLeft);
})();
