(() => {
  'use strict';

  const node = id => document.getElementById(id);
  const PAGE_SIZE = 40;
  const MIB = 1024 ** 2;
  const decimal = new Intl.NumberFormat('es-AR', {maximumFractionDigits: 1});
  const hour = new Intl.DateTimeFormat('es-AR', {timeStyle: 'medium'});
  const moment = new Intl.DateTimeFormat('es-AR', {dateStyle: 'short', timeStyle: 'medium'});
  const dayTick = new Intl.DateTimeFormat('es-AR', {day: '2-digit', month: '2-digit'});
  const hourTick = new Intl.DateTimeFormat('es-AR', {hour: '2-digit', minute: '2-digit'});
  const detail = node('processDetailDialog');
  const confirmDialog = node('processActionDialog');
  const checked = node('processActionCheck');
  const periodButtons = [...node('processHistoryPeriods').querySelectorAll('[data-hours]')];
  const previousConnections = node('processHistoryConnectionPrevious');
  const nextConnections = node('processHistoryConnectionNext');
  const charts = [
    {id: 'processCpuChart', title: 'Picos de CPU', format: percent, metrics: [{key: 'cpu_percent', label: 'CPU'}]},
    {id: 'processRamChart', title: 'Picos de RAM residente', format: bytes, metrics: [{key: 'rss_bytes', label: 'RAM'}]},
    {id: 'processNetworkChart', title: 'Picos de tráfico TCP', format: speed,
      metrics: [{key: 'rx_bps', label: 'Recibido'}, {key: 'tx_bps', label: 'Enviado'}]},
  ];

  let snapshot = null, selected = null, pending = null;
  let page = 0, historyHours = 24, connectionOffset = 0, connectionTotal = 0;
  let historySignature = '', timer, loading = false, applying = false;
  let historyLoaded = false;

  const visible = () => node('view-processes').classList.contains('active') && !document.hidden;
  const known = value => Number.isFinite(value) && value >= 0;
  const identity = row => row.pid + ':' + row.start_ticks;
  const cell = (value, className = '') => `<td class="${className}">${esc(value)}</td>`;
  const empty = (cols, text) => `<tr><td colspan="${cols}">${esc(text)}</td></tr>`;
  const protocol = value => `<td><span class="protocol">${esc(value)}</span></td>`;
  const zoom = createProcessZoom();

  function percent(value) {
    return known(value) ? decimal.format(value) + ' %' : '—';
  }

  function bytes(value) {
    if (!known(value)) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let scale = 0;
    while (value >= 1024 && scale < units.length - 1) {
      value /= 1024;
      scale++;
    }
    return decimal.format(value) + ' ' + units[scale];
  }

  function speed(value) {
    return known(value) ? bytes(value) + '/s' : '—';
  }

  function cpuMeter(value) {
    const fill = known(value) ? Math.min(value, 100) : 0;
    const ring = `<svg class="process-cpu-ring" viewBox="0 0 24 24" aria-hidden="true">
      <circle class="process-gauge-track" cx="12" cy="12" r="9"/>
      ${fill ? `<circle class="process-gauge-value" cx="12" cy="12" r="9" pathLength="100" stroke-dasharray="${fill} 100"/>` : ''}</svg>`;
    return `<span class="process-cpu-meter" title="CPU relativa a un núcleo">${ring}<span class="${value >= 80 ? 'process-high' : ''}">${esc(percent(value))}</span></span>`;
  }

  function ramMeter(value) {
    const capacity = snapshot?.memory_total_bytes;
    const label = known(value) && known(capacity) && capacity > 0
      ? `RAM residente: ${bytes(value)} de ${bytes(capacity)} (${percent(100 * value / capacity)})` : '';
    const bar = label ? `<meter class="process-ram-bar" min="0" max="${capacity}" value="${Math.min(value, capacity)}" aria-label="${esc(label)}"></meter>`
      : '<span class="process-ram-empty" aria-hidden="true"></span>';
    return `<span class="process-ram-meter"${label ? ` title="${esc(label)}"` : ''}><span>${esc(bytes(value))}</span>${bar}</span>`;
  }

  function renderList() {
    const query = node('processesFilter').value.trim().toLowerCase();
    const order = node('processesSort').value;
    const filtered = (snapshot?.processes || []).filter(row =>
      [row.name, row.pid, row.user, row.unit].some(value => String(value ?? '').toLowerCase().includes(query)));
    filtered.sort((a, b) => order === 'pid' ? a.pid - b.pid : (b[order] ?? -1) - (a[order] ?? -1) || a.pid - b.pid);
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const rows = node('processesRows');
    const focus = rows.contains(document.activeElement) ? document.activeElement.dataset.process : '';
    rows.innerHTML = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map(row => `
      <tr><td><button type="button" class="process-name-button" data-process="${esc(identity(row))}" title="${esc(row.name)}">
      <span>${esc(row.name)}</span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg></button><small class="process-learning-badge" title="${esc(row.learning_reason||'')}">${esc(learningLabel(row.learning,row.learning_status))}</small></td>
      ${cell(row.pid, 'process-id process-numeric')}<td><span class="process-user" title="${esc(row.user)}">${esc(row.user)}</span></td>
      <td>${cpuMeter(row.cpu_percent)}</td><td>${ramMeter(row.rss_bytes)}</td>
      ${cell(speed(row.rx_bps), row.rx_bps >= MIB ? 'process-numeric process-high' : 'process-numeric')}
      ${cell(speed(row.tx_bps), row.tx_bps >= MIB ? 'process-numeric process-high' : 'process-numeric')}
      ${cell(row.connections, 'process-numeric')}</tr>`
    ).join('') || empty(8, snapshot ? 'Sin procesos que coincidan.' : 'Esperando datos del servidor…');
    if (focus) rows.querySelector(`[data-process="${focus}"]`)?.focus({preventScroll: true});
    node('processesPage').textContent = `${filtered.length} procesos · Página ${page + 1} de ${pages}`;
    node('processesPrevious').disabled = page === 0;
    node('processesNext').disabled = page >= pages - 1;
  }

  function locationCells(socket) {
    return cell(socket.ip || '—') + `<td>${socket.ip ? countryMarkup(socket) : '—'}</td>` + cell(socket.isp || '—') +
      cell(socket.local_port ?? '—') + cell(socket.port ?? '—') + protocol(socket.protocol);
  }

  function learningLabel(learning,status){
    const labels={kernel:'⚪ Proceso del kernel · No aplica',waiting:'🟡 Esperando primera muestra',unavailable:'⚪ Ejecutable no identificable',error:'🔴 Error de aprendizaje',stale:'🟠 Datos de aprendizaje atrasados'};
    if(labels[status])return labels[status];
    return learning?.state==='monitoring'?'🟢 Vigilancia activa':learning?.state==='learning'?(learning.progress>=100&&learning.samples<learning.min_samples?'🟡 Esperando muestras válidas':'🟡 Aprendiendo · '+decimal.format(learning.progress)+' %'):'⚪ Sin aprendizaje disponible';
  }
  function renderLearning(row){
    const state=row?.learning;
    node('processLearningState').textContent=learningLabel(state,row?.learning_status);
    const format=(key,n)=>key==='cpu_percent'?percent(n):key==='rss_bytes'?bytes(n):speed(n);
    const labels={cpu_percent:'CPU',rss_bytes:'RAM',rx_bps:'TCP recibido',tx_bps:'TCP enviado'};
    node('processLearningInfo').textContent=row?.learning_reason|| (state?(state.state==='learning'?
      `Este VPS: desde ${moment.format(state.started_at*1000)}. Fin previsto: ${moment.format(state.ends_at*1000)}. ${state.samples} muestras válidas; mínimo ${state.min_samples}. Las alertas de este proceso están silenciadas.`:
      'Patrón guardado en este VPS. Umbrales: '+Object.entries(state.thresholds||{}).map(([key,value])=>labels[key]+' '+format(key,value)).join(' · '))+
      ' Se agrupan las instancias del mismo servicio, ejecutable y usuario. El aprendizaje continúa con el panel cerrado.':
      snapshot?.learning_error||'Todavía no se identificó un patrón. Los procesos sin ejecutable identificable no generan alertas.');
    const pendingMetrics=Object.entries(state?.metric_states||{}).filter(([,value])=>value==='learning').map(([key])=>labels[key]);
    if(state?.state==='monitoring'&&pendingMetrics.length)node('processLearningInfo').textContent+=' Métricas que siguen aprendiendo sin emitir alertas: '+pendingMetrics.join(', ')+'.';
    node('processLearningFinish').disabled=applying||!snapshot?.can_manage||state?.state!=='learning'||state.samples<state.min_samples;
    node('processLearningRestart').disabled=applying||!snapshot?.can_manage||!state;
  }
  function renderDetail(row, message = '') {
    if (!detail.open) return;
    const metrics = node('processDetailMetrics'), rows = node('processSocketRows');
    renderLearning(row);
    node('processStop').disabled = applying || !snapshot?.can_manage || !row?.can_stop;
    node('processRestart').disabled = applying || !snapshot?.can_manage || !row?.can_restart;
    node('processDetailStatus').textContent = message || (row && snapshot?.can_manage && !row.can_stop
      ? 'Este proceso está protegido o ya terminó.' : '');
    if (!row) {
      metrics.replaceChildren();
      rows.innerHTML = empty(9, 'Sin datos en vivo del proceso.');
      node('processDetailCoverage').textContent = '';
      return;
    }
    node('processDetailTitle').textContent = row.name;
    node('processDetailSubtitle').textContent = `PID ${row.pid} · ${row.user}${row.unit ? ' · ' + row.unit : ''}`;
    const items = [['CPU', cpuMeter(row.cpu_percent)], ['RAM residente', ramMeter(row.rss_bytes)],
      ['TCP recibido', esc(speed(row.rx_bps))], ['TCP enviado', esc(speed(row.tx_bps))], ['Estado', esc(row.state)]];
    metrics.innerHTML = items.map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`).join('');
    node('processDetailCoverage').textContent = !row.host_network
      ? 'No se puede identificar la red de este proceso en el espacio de red principal.'
      : 'UDP muestra los pares visibles. El tráfico TCP excluye de los totales los sockets con varios dueños.';
    rows.innerHTML = !row.sockets ? empty(9, 'Consultando conexiones…') : row.sockets.map(socket =>
      `<tr>${locationCells(socket)}${cell(socket.state + (socket.shared ? ' · Compartida' : ''))}` +
      `${cell(speed(socket.rx_bps))}${cell(speed(socket.tx_bps))}</tr>`).join('') || empty(9, 'Sin conexiones TCP o UDP visibles.');
  }

  function renderChart(chart, history, end, emptyText) {
    const plot = node(chart.id);
    const points = history?.points || [];
    const data = chart.metrics.flatMap(metric => points.map(point => point[metric.key]).filter(known));
    if (!data.length) {
      plot.innerHTML = `<p class="process-chart-empty">${esc(emptyText)}</p>`;
      return;
    }
    const limit = Math.max(1, ...data);
    const start = end - history.hours * 3600000;
    const bucket = history.bucket_seconds * 1000;
    const x = timestamp => 64 + 244 * Math.min(1, Math.max(0, (timestamp - start) / (end - start)));
    const y = value => 97 - 76 * value / limit;
    const ticks = [0, .5, 1];
    const timeFormat = history.hours === 24 ? hourTick : dayTick;
    const axes = ticks.map(ratio => {
      const ordinate = y(limit * ratio);
      return `<line x1="64" x2="308" y1="${ordinate}" y2="${ordinate}" class="process-chart-gridline"/>` +
        `<text x="60" y="${ordinate + 3}" text-anchor="end" class="process-chart-axis-label">${esc(chart.format(limit * ratio))}</text>`;
    }).join('') + ticks.map(ratio => `<text x="${64 + 244 * ratio}" y="117" text-anchor="${ratio === 0 ? 'start' : ratio === 1 ? 'end' : 'middle'}" class="process-chart-axis-label">${esc(timeFormat.format(start + (end - start) * ratio))}</text>`).join('');

    const series = chart.metrics.map((metric, index) => {
      let previous = null;
      const path = [], dots = [];
      for (const point of points) {
        const value = point[metric.key];
        if (!known(point.at_ms) || !known(value)) {
          previous = null;
          continue;
        }
        const at = x(point.at_ms).toFixed(2), top = y(value).toFixed(2);
        const joined = previous !== null && point.at_ms - previous <= bucket * 1.1;
        path.push(`${joined ? 'L' : 'M'}${at} ${top}`);
        dots.push(`<circle class="process-chart-point" cx="${at}" cy="${top}" r="1.9"><title>${esc(moment.format(point.at_ms))} · ${esc(metric.label)} ${esc(chart.format(value))}</title></circle>`);
        previous = point.at_ms;
      }
      return `<g class="process-chart-series-${index ? 'secondary' : 'main'}"><path class="process-chart-line" d="${path.join(' ')}"/>${dots.join('')}</g>`;
    }).join('');
    const legend = chart.metrics.length > 1 ? `<div class="process-chart-legend">${chart.metrics.map((metric, index) =>
      `<span><i class="process-chart-series-${index ? 'secondary' : 'main'}" aria-hidden="true"></i>${esc(metric.label)}</span>`).join('')}</div>` : '';
    plot.innerHTML = `<svg viewBox="0 0 315 125" role="img" aria-label="${esc(chart.title + ' en las últimas ' + history.hours + ' horas')}">${axes}${series}</svg>${legend}`;
  }

  function observedAt(value) {
    if (!known(value)) return '<td>—</td>';
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? `<td><time datetime="${date.toISOString()}">${esc(moment.format(date))}</time></td>` : '<td>—</td>';
  }

  function renderHistory(history, message = '') {
    historyLoaded = Boolean(history);
    const signature = JSON.stringify([history, message]);
    if (signature === historySignature) return;
    historySignature = signature;
    const points = history?.points || [];
    const info = known(history?.started_at_ms) && history.started_at_ms > 0
      ? ` · Datos desde ${moment.format(history.started_at_ms)}` : '';
    node('processHistoryStatus').textContent = message || (points.length ?
      'Picos registrados en el VPS, incluso con el panel cerrado' + info : 'Todavía no hay muestras para este período.');
    const end = Date.now();
    for (const chart of charts) renderChart(chart, history, end, message ? 'Sin datos para mostrar.' : 'Sin muestras de esta métrica.');
    const connections = history?.connections || [];
    connectionTotal = history?.connections_total || 0;
    const offset = history?.connections_offset || 0;
    const count = node('processHistoryConnectionPage');
    count.textContent = connections.length ? `${offset + 1}–${offset + connections.length} de ${connectionTotal}` : '';
    if (history?.connections_truncated) count.textContent += ' · Se alcanzó el límite de retención';
    previousConnections.disabled = connectionOffset === 0;
    nextConnections.disabled = offset + connections.length >= connectionTotal || !connections.length;
    node('processHistoryConnectionRows').innerHTML = connections.map(connection =>
      `<tr>${locationCells(connection)}${cell(connection.state || '—')}${observedAt(connection.first_seen_ms)}${observedAt(connection.last_seen_ms)}</tr>`
    ).join('') || empty(9, message || 'Sin conexiones registradas para este período.');
  }

  function schedule() {
    clearTimeout(timer);
    if (visible() && !applying) timer = setTimeout(load, 3200);
  }

  async function load() {
    clearTimeout(timer);
    if (!visible() || loading || applying) return;
    loading = true;
    const target = selected, hours = historyHours, offset = connectionOffset, zoomRequest = zoom.requestKey;
    const sameZoom = () => zoomRequest === zoom.requestKey;
    const sameHistory = () => target === selected && hours === historyHours && offset === connectionOffset;
    try {
      const query = target ? '?' + new URLSearchParams({...target, hours, connection_offset: offset, ...(zoom.active ? {detail_window:zoom.window} : {})}) : '';
      const response = await fetch('/api/processes' + query, {cache: 'no-store'});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'No se pudieron leer los procesos.');
      if(snapshot && (snapshot.boot_id!==data.boot_id || snapshot.learning_server_id && data.learning_server_id && snapshot.learning_server_id!==data.learning_server_id)){
        zoom.reset();detail.close();selected=null;renderHistory(null,'La conexión cambió. Elegí un proceso de este VPS.');
      }
      snapshot = data;
      const coverage = [!data.tcp_available && 'TCP', !data.udp_available && 'UDP'].filter(Boolean).join(' y ');
      node('processesStatus').textContent = 'Actualizado ' + hour.format(Date.now()) +
        (coverage ? ` · ${coverage} no disponible en esta muestra.` : ' · En vivo');
      renderList();
      if (target && target === selected) {
        renderDetail(data.selected, data.selected ? '' : 'El proceso ya no está activo.');
        if(sameZoom())zoom.receive(data);
        if (sameHistory()) renderHistory(data.history, data.history_error || (!data.selected && !data.history ? 'El proceso ya no está activo.' : ''));
      }
    } catch (error) {
      node('processesStatus').textContent = error.message;
      if(sameZoom())zoom.fail(error.message);
      if (target && target === selected) {
        renderDetail(null, error.message);
        if (sameHistory() && !historyLoaded) renderHistory(null, error.message);
      }
    } finally {
      loading = false;
      if ((!sameHistory() || !sameZoom()) && selected && visible()) void load();
      else schedule();
    }
  }

  function updatePeriod() {
    for (const button of periodButtons) button.setAttribute('aria-pressed', String(Number(button.dataset.hours) === historyHours));
  }

  node('processesRows').addEventListener('click', event => {
    const id = event.target.closest('[data-process]')?.dataset.process;
    const row = id && snapshot?.processes.find(item => identity(item) === id);
    if (!row) return;
    zoom.reset();
    selected = {pid: row.pid, start_ticks: row.start_ticks, boot_id: snapshot.boot_id};
    historyHours = 24;
    connectionOffset = 0;
    updatePeriod();
    detail.showModal();
    renderDetail({...row, can_stop: false, can_restart: false});
    renderHistory(null, 'Consultando el historial…');
    void load();
  });
  for (const button of periodButtons) button.addEventListener('click', () => {
    const hours = Number(button.dataset.hours);
    if (!selected || historyHours === hours) return;
    historyHours = hours;
    connectionOffset = 0;
    updatePeriod();
    renderHistory(null, 'Consultando el historial…');
    void load();
  });
  function moveConnections(change) {
    const offset = connectionOffset + change;
    if (!selected || offset < 0 || offset >= connectionTotal) return;
    connectionOffset = offset;
    previousConnections.disabled = true;
    nextConnections.disabled = true;
    node('processHistoryConnectionPage').textContent = 'Consultando conexiones…';
    void load();
  }
  previousConnections.addEventListener('click', () => moveConnections(-PAGE_SIZE));
  nextConnections.addEventListener('click', () => moveConnections(PAGE_SIZE));
  node('processDetailClose').addEventListener('click', () => detail.close());
  detail.addEventListener('close', () => { zoom.reset(); selected = null; });
  node('processesRefresh').addEventListener('click', () => void load());
  node('processesFilter').addEventListener('input', () => { page = 0; renderList(); });
  node('processesSort').addEventListener('change', () => { page = 0; renderList(); });
  node('processesPrevious').addEventListener('click', () => { page--; renderList(); });
  node('processesNext').addEventListener('click', () => { page++; renderList(); });

  function confirmAction(action) {
    const row = snapshot?.selected;
    if (!selected || !row || identity(selected) !== identity(row)) return;
    pending = {...selected, action, confirm: true};
    node('processActionTitle').textContent = action==='learning_finish'?'Finalizar aprendizaje':action==='learning_restart'?'Reiniciar aprendizaje':action === 'stop' ? 'Detener proceso' : 'Reiniciar servicio';
    node('processActionText').textContent = (action === 'restart' ? 'Se reiniciará ' + row.unit :
      row.can_restart ? 'Se detendrá ' + row.unit : 'Se solicitará la detención de ' + row.name) + ` (PID ${row.pid}).`;
    if(action==='learning_finish')node('processActionText').textContent='Se guardará el patrón medido hasta ahora en este VPS y comenzará la vigilancia de este proceso.';
    if(action==='learning_restart')node('processActionText').textContent='Se reemplazará el patrón de este proceso en este VPS por un nuevo aprendizaje de siete días. Sus alertas quedarán silenciadas durante ese período.';
    node('processActionStatus').textContent = '';
    checked.checked = false;
    node('processActionApply').disabled = true;
    confirmDialog.showModal();
  }
  node('processLearningFinish').addEventListener('click',()=>confirmAction('learning_finish'));
  node('processLearningRestart').addEventListener('click',()=>confirmAction('learning_restart'));
  node('processStop').addEventListener('click', () => confirmAction('stop'));
  node('processRestart').addEventListener('click', () => confirmAction('restart'));
  checked.addEventListener('change', () => { node('processActionApply').disabled = applying || !checked.checked; });
  node('processActionCancel').addEventListener('click', () => confirmDialog.close());
  confirmDialog.addEventListener('cancel', event => { if (applying) event.preventDefault(); });
  node('processActionApply').addEventListener('click', async () => {
    if (applying || !pending || !checked.checked) return;
    const payload = pending;
    applying = true;
    if (payload.action === 'restart') node('processRestart').dataset.running = 'true';
    clearTimeout(timer);
    node('processActionApply').disabled = true;
    node('processActionCancel').disabled = true;
    node('processActionStatus').textContent = 'Aplicando la acción…';
    try {
      const response = await fetch('/api/processes/action', {method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-StoryPulse-Token': snapshot.action_token}, body: JSON.stringify(payload)});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'No se pudo completar la acción.');
      confirmDialog.close();
      detail.close();
      selected = null;
      showToast(result.action.startsWith('learning_')?'Aprendizaje actualizado en este VPS':result.action === 'restart' ? 'Servicio reiniciado' : result.unit ? 'Servicio detenido' : 'Se envió la señal de detención');
    } catch (error) {
      node('processActionStatus').textContent = error.message;
    } finally {
      applying = false;
      delete node('processRestart').dataset.running;
      node('processActionCancel').disabled = false;
      node('processActionApply').disabled = !checked.checked;
      void load();
    }
  });
  window.addEventListener('storypulse-view', event => {
    if (event.detail === 'processes') queueMicrotask(load);
    else {
      clearTimeout(timer);
      if (detail.open && !applying) detail.close();
      if (confirmDialog.open && !applying) confirmDialog.close();
    }
  });
  document.addEventListener('visibilitychange', () => { if (visible()) void load(); else clearTimeout(timer); });
  function createProcessZoom() {
    const dialog = node('processChartDialog'), plot = node('processChartLargePlot');
    const status = node('processChartLargeStatus'), tooltip = node('processChartTooltip');
    const ranges = {'15m': 900000, '1h': 3600000, '6h': 21600000, '24h': 86400000, '48h': 172800000, '7d': 604800000};
    let chart = null, range = '1h', style = 'line', recorded = null, live = [];
    let processKey = '', latestAt = 0, receivedAt = 0, message = '', currentName = '', activeProcess = true;
    let tooltipPoints = [], geometry = null, resizeFrame = null;
    const key = () => chart && dialog.open ? chart.id + ':' + range : '';
    const currentProcessKey = () => selected ? selected.boot_id + ':' + identity(selected) : '';

    function controls() {
      node('processChartLargeTitle').textContent = chart ? chart.title : 'Actividad del proceso';
      node('processChartLargeSubtitle').textContent = currentName + (selected ? ' · PID ' + selected.pid : '');
      for (const button of node('processChartWindows').querySelectorAll('[data-window]')) {
        button.setAttribute('aria-pressed', String(button.dataset.window === range));
      }
      node('processChartStyle').value = style;
    }

    function open(id) {
      if (!selected || !snapshot?.selected || identity(snapshot.selected)!==identity(selected)) return;
      const chosen = charts.find(item => item.id === id);
      if (!chosen) return;
      if (processKey !== currentProcessKey()) { recorded = null; live = []; }
      processKey = currentProcessKey();
      chart = chosen;
      currentName = snapshot.selected.name;
      message = 'Cargando el historial detallado del VPS…';
      recorded = null;
      controls();
      if (!dialog.open) dialog.showModal();
      render();
      void load();
    }

    function reset() {
      if (dialog.open) dialog.close();
      chart = null; recorded = null; live = []; processKey = ''; latestAt = 0;
      tooltip.hidden = true;
    }

    function receive(data) {
      if (!dialog.open || !chart || processKey !== currentProcessKey()) return;
      const at = data.observed_at_ms;
      if (known(at) && at > 0) { latestAt = at; receivedAt = Date.now(); }
      activeProcess = Boolean(data.selected);
      if (data.selected && known(at) && at > (live.at(-1)?.at_ms || 0)) {
        const sample = {at_ms: at};
        for (const metric of ['cpu_percent', 'rss_bytes', 'rx_bps', 'tx_bps']) sample[metric] = data.selected[metric];
        live.push(sample);
        live = live.filter(point => point.at_ms >= at - 7200000).slice(-2400);
      }
      if (data.detail_history?.window === range) recorded = data.detail_history;
      message = data.detail_error || '';
      render();
    }

    function seriesPoints(start, end, maximum) {
      const all = [...(recorded?.points || []), ...live].filter(point => known(point.at_ms) && point.at_ms >= start && point.at_ms <= end);
      const bins = new Map(), step = Math.max(1, (end - start) / maximum);
      for (const point of all) {
        const bin = Math.floor((point.at_ms - start) / step);
        let merged = bins.get(bin);
        if (!merged) { merged = {at_ms: point.at_ms}; bins.set(bin, merged); }
        merged.at_ms = Math.max(merged.at_ms, point.at_ms);
        for (const metric of chart.metrics) {
          if (known(point[metric.key])) merged[metric.key] = Math.max(merged[metric.key] ?? 0, point[metric.key]);
        }
      }
      return [...bins.values()].sort((a, b) => a.at_ms - b.at_ms);
    }

    function render() {
      if (!chart || !dialog.open) return;
      tooltip.hidden = true;
      const end = latestAt ? latestAt + Math.max(0, Date.now() - receivedAt) : Date.now();
      const duration = ranges[range], start = end - duration;
      const width = Math.max(360, Math.round(plot.clientWidth || 900));
      const height = Math.max(230, Math.round(plot.clientHeight || 380));
      const left = width < 600 ? 74 : 95, right = 24, top = 24, bottom = 48;
      const innerWidth = width - left - right, baseline = height - bottom;
      const points = seriesPoints(start, end, style === 'bars' ? Math.max(60, Math.floor(innerWidth / 5)) : Math.max(120, Math.floor(innerWidth / 2)));
      tooltipPoints = points;
      const values = points.flatMap(point => chart.metrics.map(metric => point[metric.key]).filter(known));
      const last = live.at(-1) || recorded?.points?.at(-1);
      node('processChartValues').innerHTML = chart.metrics.map((metric, index) => {
        const observed = points.map(point => point[metric.key]).filter(known);
        const peak = observed.length ? Math.max(...observed) : null;
        return `<div class="process-zoom-value process-zoom-color-${index}"><span>${esc(metric.label)}</span><strong>${esc(chart.format(last?.[metric.key]))}</strong><small>Pico visible: ${esc(chart.format(peak))}</small></div>`;
      }).join('');
      const resolution = recorded?.bucket_seconds;
      status.textContent = message || (!recorded?.points?.length && !live.length ? 'Todavía no hay muestras en este período.' :
        (activeProcess ? '● En vivo · Actualización aproximada cada 3 segundos.' : 'Proceso finalizado · Se conserva el historial registrado.') +
        (resolution ? ` Historial: ${resolution < 60 ? resolution + ' s' : resolution / 60 + ' min'} por intervalo.` : '') +
        (known(recorded?.started_at_ms) ? ' Datos desde ' + moment.format(recorded.started_at_ms) + '.' : ''));
      node('processChartLastUpdate').textContent = latestAt ? 'Última lectura: ' + moment.format(latestAt) : '';
      if (!values.length) {
        plot.innerHTML = '<p class="process-chart-empty">Sin datos disponibles para esta métrica y período.</p>';
        geometry = null;
        return;
      }
      const ceiling = Math.max(1, ...values) * 1.1;
      const x = stamp => left + innerWidth * (stamp - start) / duration;
      const y = value => baseline - (baseline - top) * value / ceiling;
      const tickFormat = new Intl.DateTimeFormat('es-AR', range === '15m' ? {hour: '2-digit', minute: '2-digit', second: '2-digit'} :
        duration > 86400000 ? {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'} : {hour: '2-digit', minute: '2-digit'});
      const ticks = width < 600 ? 3 : 5;
      const grid = Array.from({length: 5}, (_, i) => {
        const value = ceiling * i / 4, at = y(value);
        return `<line x1="${left}" x2="${width - right}" y1="${at}" y2="${at}" class="process-zoom-grid"/><text x="${left - 10}" y="${at + 4}" text-anchor="end" class="process-zoom-axis">${esc(chart.format(value))}</text>`;
      }).join('') + Array.from({length: ticks}, (_, i) => {
        const stamp = start + duration * i / (ticks - 1), at = x(stamp);
        return `<text x="${at}" y="${height - 17}" text-anchor="${i === 0 ? 'start' : i === ticks - 1 ? 'end' : 'middle'}" class="process-zoom-axis">${esc(tickFormat.format(stamp))}</text>`;
      }).join('');
      const gap = Math.max((recorded?.bucket_seconds || 10) * 1500, duration / Math.max(60, style === 'bars' ? innerWidth / 5 : innerWidth / 2) * 1.5);
      const series = chart.metrics.map((metric, index) => {
        const segments = []; let segment = [], previous = null;
        for (const point of points) {
          const value = point[metric.key];
          if (!known(value) || previous !== null && point.at_ms - previous > gap) {
            if (segment.length) segments.push(segment);
            segment = [];
          }
          if (known(value)) segment.push({x: x(point.at_ms), y: y(value)});
          previous = known(value) ? point.at_ms : null;
        }
        if (segment.length) segments.push(segment);
        if (style === 'bars') {
          const barWidth = Math.max(1, Math.min(14, innerWidth / Math.max(1, points.length) / chart.metrics.length * .75));
          return `<g class="process-zoom-series-${index}">${segments.flat().map(point => `<rect class="process-zoom-bar" x="${point.x - barWidth * chart.metrics.length / 2 + index * barWidth}" y="${point.y}" width="${barWidth}" height="${Math.max(.8, baseline - point.y)}"/>`).join('')}</g>`;
        }
        return `<g class="process-zoom-series-${index}">${segments.map(segment => {
          const path = segment.map((point, i) => `${i ? 'L' : 'M'}${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(' ');
          return (style === 'area' && segment.length > 1 ? `<path class="process-zoom-area" d="${path} L${segment.at(-1).x} ${baseline} L${segment[0].x} ${baseline} Z"/>` : '') +
            `<path class="process-zoom-line" d="${path}"/>` + (segment.length === 1 ? `<circle cx="${segment[0].x}" cy="${segment[0].y}" r="3" class="process-zoom-dot"/>` : '');
        }).join('')}</g>`;
      }).join('');
      plot.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(chart.title + ', ventana ' + range)}">${grid}${series}</svg>`;
      geometry = {left, innerWidth, start, duration};
    }

    for (const item of charts) {
      const small = node(item.id), figure = small.closest('figure');
      figure.querySelector('button[data-expand-chart]').addEventListener('click', () => open(item.id));
      small.addEventListener('click', () => open(item.id));
      small.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(item.id); } });
    }
    node('processChartWindows').addEventListener('click', event => {
      const window = event.target.closest('[data-window]')?.dataset.window;
      if (!Object.hasOwn(ranges, window) || range === window) return;
      range = window; recorded = null; message = 'Cargando el período elegido…'; controls(); render(); void load();
    });
    node('processChartStyle').addEventListener('change', event => {
      if (!['line', 'area', 'bars'].includes(event.target.value)) return;
      style = event.target.value; render();
    });
    node('processChartLargeClose').addEventListener('click', () => dialog.close());
    node('processChartMaximize').addEventListener('click', () => {
      const expanded = dialog.classList.toggle('is-maximized');
      node('processChartMaximize').textContent = expanded ? 'Restaurar tamaño' : 'Maximizar';
      node('processChartMaximize').setAttribute('aria-pressed', String(expanded));
      requestAnimationFrame(render);
    });
    dialog.addEventListener('close', () => { tooltip.hidden = true; });
    plot.addEventListener('pointerleave', () => { tooltip.hidden = true; });
    plot.addEventListener('pointermove', event => {
      if (!geometry || !tooltipPoints.length || !chart) return;
      const bounds = plot.getBoundingClientRect(), localX = event.clientX - bounds.left;
      const stamp = geometry.start + (localX - geometry.left) / geometry.innerWidth * geometry.duration;
      const nearest = tooltipPoints.reduce((best, point) => Math.abs(point.at_ms - stamp) < Math.abs(best.at_ms - stamp) ? point : best);
      tooltip.textContent = moment.format(nearest.at_ms) + '\n' + chart.metrics.map(metric => metric.label + ': ' + chart.format(nearest[metric.key])).join('\n');
      tooltip.hidden = false;
      tooltip.style.left = Math.max(8, Math.min(bounds.width - tooltip.offsetWidth - 8, localX + 14)) + 'px';
      tooltip.style.top = Math.max(8, Math.min(bounds.height - tooltip.offsetHeight - 8, event.clientY - bounds.top + 14)) + 'px';
    });
    new ResizeObserver(() => {
      cancelAnimationFrame(resizeFrame);
      resizeFrame = requestAnimationFrame(render);
    }).observe(plot);
    return {open, reset, receive, fail(text) { message = text; render(); }, get active() { return Boolean(chart && dialog.open); }, get window() { return range; }, get requestKey() { return key(); }};
  }

  renderList();
  void window.PanelAccess.ready.then(load);
})();
