<template>
  <div class="screen">
    <div class="gradient" />
    <header class="header">
      <img :src="starIcon" alt="" class="star-icon" width="27" height="30" />
      <h1 class="title">Astra</h1>
      <p class="version">dev version {{ version }}</p>
      <p class="date">02.2026</p>
    </header>

    <div class="power-wrap">
      <button
        class="power"
        :class="{ connected }"
        :disabled="connecting"
        @click="toggle"
      >
        <img :src="powerIcon" alt="Power" class="power-icon-img" width="61" height="61" />
        <span class="power-label">{{ connected ? 'ВЫКЛ' : 'ВКЛ' }}</span>
      </button>
    </div>

    <div class="status-row">
      <span class="status-badge" :class="{ connected }">
        {{ statusText }}
      </span>
      <span v-if="connected" class="server-row">
        <span class="server-country">🇳🇱 Amsterdam</span>
        <span v-if="ping != null" class="ping">{{ ping }} ms</span>
        <span v-else class="ping">— ms</span>
      </span>
    </div>

    <footer class="footer">
      <button class="open-logs" @click="openLogs">Logs</button>
      <p class="powered">powered by ddy</p>
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue';
import starIcon from './assets/star.svg';
import powerIcon from './assets/power.svg';

const version = '0.1';
const connected = ref(false);
const connecting = ref(false);
const ping = ref(null);

const statusText = computed(() => {
  if (connecting.value) return 'Connecting…';
  return connected.value ? 'CONNECTED' : 'DISCONNECTED';
});

async function toggle() {
  if (connecting.value) return;
  if (connected.value) {
    await window.astra.disconnect();
    connected.value = false;
    ping.value = null;
    return;
  }
  connecting.value = true;
  try {
    const res = await window.astra.connect();
    if (res.ok) {
      connected.value = true;
      window.astra.startPing();
    } else {
      alert(res.error || 'Connection failed');
    }
  } finally {
    connecting.value = false;
  }
}

function openLogs() {
  window.astra.openLogs();
}

onMounted(async () => {
  const s = await window.astra.getStatus();
  connected.value = s.connected;
  if (s.connected) window.astra.startPing();
  window.astra.onPing((ms) => {
    ping.value = ms;
  });
});

onUnmounted(() => {});
</script>

<style scoped>
.screen {
  width: 300px;
  height: 600px;
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  overflow: hidden;
}

.gradient {
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, #080D16 0%, #0C1220 100%);
  z-index: 0;
}

.header {
  position: relative;
  z-index: 1;
  padding-top: 40px;
  text-align: center;
}

.star-icon {
  display: block;
  margin: 0 auto 8px;
  opacity: 0.95;
}

.title {
  font-size: 26px;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: #fff;
}

.version {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
  margin-top: 2px;
}

.date {
  font-size: 10px;
  color: rgba(255, 255, 255, 0.35);
  margin-top: 2px;
}

.power-wrap {
  position: relative;
  z-index: 1;
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 180px;
}

.power {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  border: none;
  background: rgba(0, 157, 255, 0.2);
  color: #fff;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  box-shadow: 0 0 0 1px rgba(255,255,255,0.08), 0 0 30px rgba(0, 157, 255, 0.15);
  transition: background 0.2s, transform 0.1s;
}

.power:hover:not(:disabled) {
  background: rgba(0, 157, 255, 0.3);
  transform: scale(1.03);
}

.power:disabled {
  opacity: 0.85;
  cursor: wait;
}

.power.connected {
  background: rgba(0, 142, 109, 0.3);
  box-shadow: 0 0 0 1px rgba(255,255,255,0.08), 0 0 30px rgba(0, 142, 109, 0.2);
}

.power.connected:hover:not(:disabled) {
  background: rgba(0, 142, 109, 0.45);
}

.power-icon-img {
  width: 52px;
  height: 52px;
  pointer-events: none;
}

.power-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.status-row {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding-bottom: 20px;
}

.status-badge {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.05em;
  color: rgba(255, 255, 255, 0.5);
}

.status-badge.connected {
  color: #008E6D;
}

.server-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.6);
}

.server-country {
  font-size: 12px;
}

.ping {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.5);
}

.footer {
  position: relative;
  z-index: 1;
  padding-bottom: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.open-logs {
  padding: 8px 24px;
  border-radius: 9px;
  border: 1px solid rgba(255, 255, 255, 0.25);
  background: rgba(255, 255, 255, 0.06);
  color: rgba(255, 255, 255, 0.9);
  font-size: 13px;
  font-family: inherit;
  cursor: pointer;
  transition: background 0.2s, color 0.2s;
}

.open-logs:hover {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
}

.powered {
  font-size: 10px;
  color: rgba(255, 255, 255, 0.3);
}
</style>
