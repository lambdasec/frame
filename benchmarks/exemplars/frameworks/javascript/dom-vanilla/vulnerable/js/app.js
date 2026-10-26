$(function () {
  var name = decodeURIComponent(location.hash.slice(1));
  $('#welcome').html('Hello ' + name);  // frame-expect: CWE-79

  $('#search').on('submit', function (e) {
    e.preventDefault();
    var term = new URLSearchParams(location.search).get('q');
    $('#results').append('<li>' + term + '</li>');  // frame-expect: CWE-79
  });
});

window.addEventListener('message', function (event) {
  document.getElementById('panel').innerHTML = event.data.html;  // frame-expect: CWE-79
});

function goBack() {
  var ret = new URLSearchParams(location.search).get('return');
  window.location = ret;  // frame-expect: CWE-601
}

function loadWidget() {
  var src = location.hash.slice(1);
  document.write('<script src="' + src + '"><\/script>');  // frame-expect: CWE-79
}
