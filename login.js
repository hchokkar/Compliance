const validEmail = "hchokkar@digitide.com";
const validPassword = "Sh@n2026";

const form = document.getElementById("loginForm");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const messageEl = document.getElementById("validationMessage");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  messageEl.textContent = "";
  messageEl.className = "message";

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (email === validEmail && password === validPassword) {
    localStorage.setItem("loggedInUser", email);
    window.location.href = "dashboard.html";
  } else {
    messageEl.textContent = "Invalid user ID or password. Please try again.";
    messageEl.classList.add("error");
  }
});
