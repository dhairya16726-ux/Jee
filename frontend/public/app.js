const API_BASE = window.API_BASE || 'http://localhost:4000';

const step1 = document.getElementById('step1');
const step2 = document.getElementById('step2');
const step3 = document.getElementById('step3');
const loginForm = document.getElementById('loginForm');
const statusEl = document.getElementById('status');
const strengthEl = document.getElementById('strength');

const state = {
  name: '',
  mobileNo: '',
  password: '',
};

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#b91c1c' : '#065f46';
}

function validateMobile(mobileNo) {
  return /^\d{10}$/.test(mobileNo);
}

function passwordErrors(password) {
  const errors = [];
  if (password.length < 8) errors.push('min 8 chars');
  if (!/[A-Z]/.test(password)) errors.push('1 uppercase');
  if (!/[a-z]/.test(password)) errors.push('1 lowercase');
  if (!/\d/.test(password)) errors.push('1 number');
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(password)) errors.push('1 special char');
  return errors;
}

document.getElementById('password').addEventListener('input', (e) => {
  const errors = passwordErrors(e.target.value);
  strengthEl.textContent = errors.length ? `Needs: ${errors.join(', ')}` : 'Strong password ✅';
});

step1.addEventListener('submit', (e) => {
  e.preventDefault();

  const name = document.getElementById('name').value.trim();
  const mobileNo = document.getElementById('mobileNo').value.trim();

  if (!name) return setStatus('Name is required.', true);
  if (!validateMobile(mobileNo)) return setStatus('Mobile number must be 10 digits.', true);

  state.name = name;
  state.mobileNo = mobileNo;
  step1.classList.add('hidden');
  step2.classList.remove('hidden');
  setStatus('Step 1 complete. Set your password.');
});

step2.addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  const errors = passwordErrors(password);

  if (errors.length) return setStatus(`Password invalid: ${errors.join(', ')}`, true);
  if (password !== confirmPassword) return setStatus('Passwords do not match.', true);

  state.password = password;

  const response = await fetch(`${API_BASE}/auth/register/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: state.name,
      mobileNo: state.mobileNo,
      password: state.password,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    setStatus(data.error || 'Registration failed.', true);
    return;
  }

  step2.classList.add('hidden');
  step3.classList.remove('hidden');

  const msg = data.mockOtp
    ? `OTP sent. (mock OTP: ${data.mockOtp})`
    : 'OTP sent to your mobile number.';
  setStatus(msg);
});

step3.addEventListener('submit', async (e) => {
  e.preventDefault();
  const otp = document.getElementById('otp').value.trim();

  if (!/^\d{6}$/.test(otp)) return setStatus('OTP must be a 6-digit number.', true);

  const response = await fetch(`${API_BASE}/auth/register/verify-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobileNo: state.mobileNo, otp }),
  });

  const data = await response.json();
  if (!response.ok) return setStatus(data.error || 'OTP verification failed.', true);

  step3.classList.add('hidden');
  loginForm.classList.remove('hidden');
  document.getElementById('loginMobile').value = state.mobileNo;
  setStatus('Account verified. Please login.');
});

document.getElementById('resendOtp').addEventListener('click', async () => {
  const response = await fetch(`${API_BASE}/auth/register/resend-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobileNo: state.mobileNo }),
  });

  const data = await response.json();
  if (!response.ok) return setStatus(data.error || 'Unable to resend OTP.', true);

  setStatus(data.mockOtp ? `OTP resent. (mock OTP: ${data.mockOtp})` : 'OTP resent.');
});

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const mobileNo = document.getElementById('loginMobile').value.trim();
  const password = document.getElementById('loginPassword').value;

  const response = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobileNo, password }),
  });

  const data = await response.json();

  if (!response.ok) return setStatus(data.error || 'Login failed.', true);

  setStatus(`Login successful. JWT: ${data.token.substring(0, 25)}...`);
});
