// ===== FRONTEND SCRIPT (loaded by templates/base.html) =====
// Any <form data-confirm="..."> asks the user to confirm before it is submitted
// (used for the Delete button on the staff dashboard).
document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();          // user clicked Cancel -> do not delete
  }
});
