$(function () {
  var name = decodeURIComponent(location.hash.slice(1));
  $('#welcome').text('Hello ' + name);

  $('#search').on('submit', function (e) {
    e.preventDefault();
    var term = new URLSearchParams(location.search).get('q');
    $('#results').append($('<li>').text(term));
  });
});

window.addEventListener('message', function (event) {
  if (event.origin !== 'https://app.example.com') return;
  document.getElementById('panel').textContent = event.data.html;
});

function goBack() {
  var ret = new URLSearchParams(location.search).get('return');
  if (ret && ret.startsWith('/') && !ret.startsWith('//')) {
    window.location = ret;
  }
}

function loadWidget() {
  var src = location.hash.slice(1);
  var known = ['/widgets/chat.js', '/widgets/help.js'];
  if (known.includes(src)) {
    var s = document.createElement('script');
    s.src = src;
    document.body.appendChild(s);
  }
}
