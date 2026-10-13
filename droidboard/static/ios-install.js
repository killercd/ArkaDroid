(() => {
  const panel = () => document.querySelector('[data-ios-install]');
  let polling = false;
  async function call(url, body) {
    const response = await fetch(url, {
      method: body ? 'POST' : 'GET', body, cache: 'no-store',
      headers: {'Accept': 'application/json'},
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  }
  function jobUrl(p) { return p.dataset.jobUrl.replace('JOB_ID', encodeURIComponent(p.dataset.job)); }
  function message(p, text) { p.querySelector('[data-ios-status]').textContent = text; }
  function render(p, job) {
    if (!p.isConnected) return;
    p.dataset.job = job.id;
    const active = ['running', 'waiting'].includes(job.state);
    p.dataset.active = active ? '1' : '';
    message(p, job.message);
    p.querySelectorAll('[data-ios-start] input, [data-ios-start] select, [data-ios-start] button')
      .forEach(el => { el.disabled = active; });
    p.querySelector('[data-ios-cancel]').hidden = !active || !job.cancellable;
    const form = p.querySelector('[data-ios-answer]');
    const changed = form.dataset.challenge !== job.challenge;
    form.hidden = job.state !== 'waiting';
    if (changed || form.hidden) {
      form.reset();
      form.dataset.challenge = job.challenge;
    }
    if (!form.hidden && changed) {
      const field = form.elements.answer;
      field.type = job.prompt === 'apple_id' ? 'email' : 'password';
      field.inputMode = job.prompt === 'apple_id' ? 'email' : 'text';
      p.querySelector('[data-ios-prompt]').textContent = {
        apple_id: 'Apple ID', password: 'Apple ID password',
        verification_code: 'Apple verification code (or resend)',
      }[job.prompt];
      field.focus();
    }
  }
  document.addEventListener('submit', async event => {
    const form = event.target;
    if (!form.matches('[data-ios-start], [data-ios-answer]')) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const p = form.closest('[data-ios-install]');
    if (form.dataset.sending) return;
    form.dataset.sending = '1';
    const body = new FormData(form);
    body.set('csrf_token', p.dataset.csrf);
    const answering = form.matches('[data-ios-answer]');
    if (answering) {
      body.set('action', 'answer');
      body.set('challenge', form.dataset.challenge);
      form.reset();
    }
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      message(p, answering ? 'Continuing…' : 'Uploading and preparing installation…');
      const data = await call(answering ? jobUrl(p) : p.dataset.installUrl, body);
      render(p, data.job);
    } catch (error) { message(p, error.message); }
    finally {
      body.delete('answer');
      delete form.dataset.sending;
      button.disabled = !answering && p.dataset.active === '1';
    }
  }, true);
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-ios-devices], [data-ios-cancel]');
    if (!button) return;
    const p = button.closest('[data-ios-install]');
    button.disabled = true;
    try {
      if (button.matches('[data-ios-devices]')) {
        const url = new URL(p.dataset.devicesUrl, location.href);
        url.searchParams.set('network', p.querySelector('[name="network"]').checked ? '1' : '0');
        const data = await call(url);
        const select = p.querySelector('[name="udid"]');
        select.replaceChildren(new Option('Select a device', ''));
        data.devices.forEach(udid => select.add(new Option(udid, udid)));
        if (data.devices.length === 1) select.value = data.devices[0];
        p.querySelector('[data-ios-device-message]').textContent = data.devices.length
          ? `${data.devices.length} device(s) found.` : data.message;
      } else {
        const body = new FormData();
        body.set('csrf_token', p.dataset.csrf);
        body.set('action', 'cancel');
        await call(jobUrl(p), body);
        message(p, 'Cancelling…');
      }
    } catch (error) { message(p, error.message); }
    finally { button.disabled = false; }
  });
  setInterval(async () => {
    const p = panel();
    if (!p || !p.dataset.job || polling || p.dataset.active === 'done') return;
    polling = true;
    try {
      const data = await call(jobUrl(p));
      render(p, data.job);
      if (!['running', 'waiting'].includes(data.job.state)) p.dataset.active = 'done';
    } catch (error) {
      message(p, `${error.message} Reload the page to reconnect.`);
      p.dataset.active = 'done';
    } finally { polling = false; }
  }, 1000);
})();
