/* The public code contains no password or decryption key. All website assets
 * are inside one authenticated, encrypted package, including images and PDF. */
(() => {
  'use strict';
  const form = document.getElementById('unlock-form');
  const input = document.getElementById('password');
  const submit = document.getElementById('unlock');
  const message = document.getElementById('message');
  const gate = document.getElementById('gate');
  const frame = document.getElementById('view');
  const lock = document.getElementById('lock');
  const decode = text => Uint8Array.from(atob(text), character => character.charCodeAt(0));
  const utf8 = new TextDecoder();
  let bundle = null, resources = new Map(), currentRoute = null, generation = 0;
  const normalize = pathname => pathname.replace(/index\.html$/, '').replace(/\/?$/, '/');

  function scrollToFragment(fragment) {
    if (!fragment) return;
    let target;
    try { target = frame.contentDocument.getElementById(decodeURIComponent(fragment.slice(1))); } catch { return; }
    if (!target) return;
    for (let node = target; node; node = node.parentElement) if (node.tagName === 'DETAILS') node.open = true;
    frame.contentWindow.requestAnimationFrame(() => target.scrollIntoView({block:'start'}));
  }
  function assetPath(value, route) {
    try {
      const url = new URL(value, location.origin + route);
      return url.origin === location.origin ? url.pathname : null;
    } catch { return null; }
  }
  function rewriteScript(source) {
    // Existing interactive image selectors use quoted root-relative paths.
    return source.replace(/(['"])(\/[^'"\s]+)\1/g, (literal, quote, url) => resources.has(url) ? JSON.stringify(resources.get(url)) : literal);
  }
  function navigate(route, fragment = '', push = false) {
    if (!bundle) return;
    route = normalize(route);
    if (!bundle.pages[route]) { route = '/'; fragment = ''; }
    if (push) history.pushState(null, '', route + fragment);
    if (route === currentRoute) { scrollToFragment(fragment); return; }
    currentRoute = route;
    const documentCopy = new DOMParser().parseFromString(bundle.pages[route], 'text/html');
    const base = documentCopy.createElement('base');
    base.href = location.origin + route;
    documentCopy.head.prepend(base);
    for (const link of documentCopy.querySelectorAll('link[rel="stylesheet"]')) {
      const source = bundle.assets[assetPath(link.getAttribute('href'), route)];
      if (!source) throw new Error('Missing encrypted stylesheet.');
      const style = documentCopy.createElement('style'); style.textContent = utf8.decode(decode(source.data)); link.replaceWith(style);
    }
    for (const script of documentCopy.querySelectorAll('script[src]')) {
      const source = bundle.assets[assetPath(script.getAttribute('src'), route)];
      if (!source) throw new Error('Missing encrypted script.');
      const inline = documentCopy.createElement('script'); inline.textContent = rewriteScript(utf8.decode(decode(source.data)));
      script.remove(); documentCopy.body.append(inline);
    }
    for (const element of documentCopy.querySelectorAll('[src],[href],[poster]')) {
      for (const attribute of ['src','href','poster']) {
        const value = element.getAttribute(attribute);
        if (!value || value.startsWith('#')) continue;
        const url = resources.get(assetPath(value, route));
        if (url) element.setAttribute(attribute, url);
      }
    }
    document.title = documentCopy.title;
    frame.title = documentCopy.title;
    frame.onload = () => {
      if (!bundle) return;
      frame.contentDocument.addEventListener('click', event => {
        const anchor = event.target.closest?.('a[href]');
        if (!anchor || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || anchor.hasAttribute('download')) return;
        const raw = anchor.getAttribute('href');
        if (/^(blob:|data:|mailto:|tel:)/i.test(raw)) return;
        const url = new URL(raw, location.origin + currentRoute);
        if (url.origin !== location.origin || !bundle.pages[normalize(url.pathname)]) return;
        if (anchor.target === '_blank') return;
        event.preventDefault(); navigate(url.pathname, url.hash, true);
      }, true);
      scrollToFragment(fragment);
    };
    frame.srcdoc = '<!doctype html>' + documentCopy.documentElement.outerHTML;
  }
  function closePortfolio() {
    generation++;
    bundle = null; currentRoute = null;
    frame.onload = null; frame.srcdoc = ''; frame.hidden = true;
    for (const url of resources.values()) URL.revokeObjectURL(url);
    resources.clear(); gate.hidden = false; lock.hidden = true;
    input.value = ''; message.textContent = ''; document.title = 'Private portfolio';
    input.focus();
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const attempt = ++generation;
    submit.disabled = true; message.textContent = 'Unlocking…';
    try {
      if (!crypto.subtle || typeof DecompressionStream === 'undefined') throw new Error('unsupported');
      const response = await fetch('/vault.json', {cache:'no-store'});
      if (!response.ok) throw new Error('network');
      const config = await response.json();
      if (config.version !== 1 || config.iterations !== 600000 || !/^vault-[a-f0-9]{20}\.bin$/.test(config.payload)) throw new Error('format');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(input.value), 'PBKDF2', false, ['deriveKey']);
      input.value = '';
      const key = await crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt:decode(config.salt), iterations:config.iterations}, material, {name:'AES-GCM', length:256}, false, ['decrypt']);
      const encrypted = await fetch('/' + config.payload);
      if (!encrypted.ok) throw new Error('network');
      const plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv:decode(config.iv), additionalData:new TextEncoder().encode('portfolio-v1'), tagLength:128}, key, await encrypted.arrayBuffer());
      const stream = new Blob([plaintext]).stream().pipeThrough(new DecompressionStream('gzip'));
      const decoded = JSON.parse(await new Response(stream).text());
      if (attempt !== generation) return;
      if (decoded.version !== 1 || !decoded.pages?.['/'] || !decoded.assets?.['/resume.pdf']) throw new Error('format');
      bundle = decoded;
      for (const [name, asset] of Object.entries(bundle.assets)) resources.set(name, URL.createObjectURL(new Blob([decode(asset.data)], {type:asset.type})));
      navigate(location.pathname, location.hash);
      gate.hidden = true; frame.hidden = false; lock.hidden = false; message.textContent = '';
    } catch (error) {
      closePortfolio();
      message.textContent = error.message === 'unsupported' ? 'Use a current browser over HTTPS to unlock this portfolio.' : error.message === 'network' ? 'The encrypted portfolio could not load. Please try again.' : 'That password did not unlock the portfolio.';
    } finally { submit.disabled = false; }
  });
  lock.addEventListener('click', closePortfolio);
  window.addEventListener('popstate', () => { if (bundle) navigate(location.pathname, location.hash); });
  // Secrets and decrypted files are held in memory, never in browser storage.
  window.addEventListener('pagehide', closePortfolio);
})();
