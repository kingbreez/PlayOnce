// PlayOnce Service Worker
// Caches app shell for instant load, passes video/API requests through

const CACHE_NAME = 'playonce-v1';
const CACHE_URLS = [
  '/',
  '/index.html',
  'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&display=swap',
  'https://cdn.jsdelivr.net/npm/hls.js@1.5.7/dist/hls.min.js',
  'https://js.stripe.com/v3/'
];

// Install — cache app shell
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(CACHE_URLS.filter(u => !u.startsWith('https://js.stripe.com'))))
      .catch(() => {}) // never block install
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch strategy:
// - API calls: network only (always fresh)
// - Video/HLS: network only (signed URLs, can't cache)
// - App shell (HTML/CSS/fonts): cache first, fallback to network
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Always bypass cache for:
  // - API endpoints
  // - Stripe
  // - CloudFront video/HLS content
  // - External APIs
  if (
    url.hostname.includes('execute-api') ||
    url.hostname.includes('cloudfront.net') ||
    url.hostname.includes('stripe.com') ||
    url.pathname.includes('/api/') ||
    url.pathname.includes('.m3u8') ||
    url.pathname.includes('.ts') ||
    url.pathname.includes('.mp4')
  ) {
    return; // let browser handle normally
  }

  // App shell — cache first
  if (event.request.method === 'GET') {
    event.respondWith(
      caches.match(event.request).then(cached => {
        const network = fetch(event.request)
          .then(response => {
            // Update cache with fresh version
            if (response.ok) {
              const clone = response.clone();
              caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone)).catch(() => {});
            }
            return response;
          })
          .catch(() => cached); // offline fallback to cache
        return cached || network;
      })
    );
  }
});

// Push notifications (future feature — placeholder)
self.addEventListener('push', event => {
  if (!event.data) return;
  try {
    const data = event.data.json();
    self.registration.showNotification(data.title || 'PlayOnce', {
      body: data.body || 'New drop available',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: data.tag || 'playonce',
      data: { url: data.url || '/' }
    });
  } catch(e) {}
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(clientList => {
      if (clientList.length) return clientList[0].focus();
      return clients.openWindow(event.notification.data?.url || '/');
    })
  );
});
