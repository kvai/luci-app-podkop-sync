'use strict';
'require view';
'require rpc';
'require uci';
'require ui';
'require dom';
'require form';

/* ubus-методы провайдера luci.podkop_sub */
var callSync = rpc.declare({ object: 'luci.podkop_sub', method: 'sync' });
var callStatus = rpc.declare({ object: 'luci.podkop_sub', method: 'status' });

/* Разбор vless:// ссылки для таблицы (имя/протокол/сеть/хост/порт).
   Полностью percent-encoded фрагмент декодируется здесь. */
function parseVless(link) {
	var m = /^vless:\/\/([^@]+)@(.+):(\d+)(?:\?([^#]*))?(?:#(.*))?$/i.exec(link);
	if (!m)
		return null;

	var params = {};
	(m[4] || '').split('&').forEach(function(kv) {
		if (!kv) return;
		var i = kv.indexOf('=');
		var k = (i < 0) ? kv : kv.slice(0, i);
		var v = (i < 0) ? '' : kv.slice(i + 1);
		try { params[k] = decodeURIComponent(v.replace(/\+/g, ' ')); }
		catch (e) { params[k] = v; }
	});

	var name = m[5] || '';
	try { name = decodeURIComponent(name); } catch (e) {}

	var sec = params.security || 'none';
	var net = params.type || 'tcp';
	var proto = 'VLESS';
	if (sec === 'reality') proto += ' · REALITY';
	else if (sec === 'tls') proto += ' · TLS';

	return { name: name || '—', proto: proto, net: net, host: m[2], port: m[3] };
}

function fmtTime(epoch) {
	epoch = parseInt(epoch, 10);
	if (!epoch)
		return _('никогда');
	return new Date(epoch * 1000).toLocaleString();
}

/* Ждём, пока LuCI реально закоммитит изменения (uci.changes станет пустым),
   чтобы sync читал уже применённый конфиг. tries — максимум попыток по 300мс. */
function waitApplied(tries) {
	return uci.changes().then(function(ch) {
		var has = false, k;
		for (k in (ch || {})) {
			if (ch[k] && ch[k].length) { has = true; break; }
		}
		if (!has || tries <= 0)
			return true;
		return new Promise(function(res) { window.setTimeout(res, 300); })
			.then(function() { return waitApplied(tries - 1); });
	});
}

function renderStatusInner(st) {
	st = st || {};
	var ok = (st.status === 'ok');
	var color = ok ? '#4caf50' : (st.status === 'error' ? '#f44336' : '#9e9e9e');
	var label = ok ? _('OK') : (st.status === 'error' ? _('Ошибка') : _('не запускалось'));

	return [
		E('p', {}, [
			E('strong', {}, _('Статус') + ': '),
			E('span', { 'style': 'color:' + color + ';font-weight:bold' }, label),
			st.message ? E('span', { 'style': 'margin-left:1em;color:#888' }, String(st.message)) : ''
		]),
		E('p', {}, [
			E('strong', {}, _('Нод') + ': '),
			E('span', {}, String(st.count || 0)),
			E('strong', { 'style': 'margin-left:2em' }, _('Обновлено') + ': '),
			E('span', {}, fmtTime(st.last_update)),
			E('strong', { 'style': 'margin-left:2em' }, _('Секция') + ': '),
			E('span', {}, String(st.section || 'main'))
		])
	];
}

function renderNodesTable(nodes) {
	nodes = Array.isArray(nodes) ? nodes : [];
	var rows = [];
	nodes.forEach(function(link) {
		var n = parseVless(link);
		if (!n) return;
		rows.push([
			n.name,
			E('span', { 'class': 'ifacebadge' }, n.proto + ' / ' + n.net),
			n.host,
			n.port
		]);
	});

	var tbl = E('table', { 'class': 'table', 'id': 'podkop-nodes' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Название')),
			E('th', { 'class': 'th' }, _('Протокол')),
			E('th', { 'class': 'th' }, _('Хост / IP')),
			E('th', { 'class': 'th' }, _('Порт'))
		])
	]);
	cbi_update_table(tbl, rows, E('em', _('Нод пока нет — запустите обновление.')));
	return tbl;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('podkop_sub'),
			uci.load('podkop'),
			callStatus().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var status = data[2] || {};

		/* секции podkop (тип 'section') для выпадающего списка */
		var sections = uci.sections('podkop', 'section').map(function(s) {
			return s['.name'];
		});

		/* ---- форма настроек (нативный LuCI, даёт Save & Apply) ---- */
		var m = new form.Map('podkop_sub', _('Podkop Sync'),
			_('Скачивает подписки на прокси, разбирает их в vless-ссылки и применяет ' +
			  'к секции Podkop (режим URLTest).'));

		var s = m.section(form.NamedSection, 'config', 'podkop_sub');
		s.anonymous = true;

		var o;

		o = s.option(form.Flag, 'enabled', _('Включить сервис'),
			_('Когда выключено — автообновление по расписанию отключено ' +
			  '(ручное «Обновить сейчас» продолжает работать).'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'url', _('Ссылки на подписки'),
			_('JSON, Base64 и обычные списки vless:// определяются автоматически. ' +
			  'По одной ссылке в строке.'));
		o.placeholder = 'https://example.com/sub';

		o = s.option(form.TextValue, 'manual_nodes', _('Ручные ноды (vless://)'),
			_('Вставьте свои серверы, по одной ссылке vless:// в строке — они ' +
			  'добавляются в секцию наравне с нодами подписки и не затираются ' +
			  'при обновлении. Строки без vless:// игнорируются.'));
		o.rows = 6;
		o.monospace = true;
		o.placeholder = 'vless://uuid@host:443?type=tcp&security=reality&...#Имя';

		o = s.option(form.ListValue, 'section', _('Целевая секция Podkop'),
			_('Ноды пишутся в urltest_proxy_links выбранной секции.'));
		if (sections.length === 0) o.value('main', 'main');
		sections.forEach(function(sec) { o.value(sec, sec); });
		o.default = 'main';

		o = s.option(form.Flag, 'deduplicate', _('Удалять дубликаты серверов'));
		o.default = '1';

		o = s.option(form.Flag, 'preserve_manual', _('Сохранять внешние ноды'),
			_('Сохранять ноды, добавленные в секцию напрямую в podkop (не через ' +
			  'поле выше). Выкл — секция = только ручные ноды из поля + подписка.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.ListValue, 'cron', _('Расписание автообновления'),
			_('Запускает синхронизацию автоматически через cron.'));
		o.value('0', _('Выключено'));
		o.value('6', _('Каждые 6 часов'));
		o.value('12', _('Каждые 12 часов'));
		o.value('24', _('Раз в сутки'));
		o.default = '24';

		o = s.option(form.Value, 'user_agent', _('User-Agent'),
			_('Отправляется curl при скачивании подписок.'));
		o.default = 'v2rayNG/1.9.5';

		/* ---- статус + кнопка + таблица (вне формы) ---- */
		var statusBox = E('div', { 'id': 'podkop-status' }, renderStatusInner(status));
		var nodesBox = renderNodesTable(status.nodes);

		function onSyncNow() {
			var self = this;
			/* Штатное сохранение+применение (корректно гасит бейдж «unsaved» и
			   не падает при отсутствии изменений), затем ЖДЁМ фактического
			   commit'а и только потом синкаем — иначе sync читает старый конфиг
			   (баг «срабатывает со второго раза»). */
			return self.handleSaveApply(null, '0').then(function() {
				return waitApplied(15);
			}).then(function() {
				ui.showModal(_('Обновление подписок…'), [
					E('p', { 'class': 'spinning' }, _('Скачивание и разбор, подождите…'))
				]);
				return callSync();
			}).then(function(res) {
				ui.hideModal();
				res = res || {};

				dom.content(statusBox, renderStatusInner(res));
				var newNodes = renderNodesTable(res.nodes);
				var old = document.getElementById('podkop-nodes');
				if (old && old.parentNode) old.parentNode.replaceChild(newNodes, old);

				if (res.status === 'ok')
					ui.addNotification(null, E('p', _('Обновлено: %s нод.').format(res.count || 0)), 'info');
				else
					ui.addNotification(null, E('p', String(res.message || _('Обновление не удалось.'))), 'danger');
			}).catch(function(e) {
				ui.hideModal();
				ui.addNotification(null, E('p', _('Обновление не удалось') + ': ' + e), 'danger');
			});
		}

		var extra = E('div', {}, [
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Последнее обновление')),
				E('p', {}, [
					E('button', {
						'class': 'btn cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(this, onSyncNow)
					}, _('Обновить сейчас')),
					E('span', { 'style': 'margin-left:1em;color:#888' },
						_('Сохраняет настройки выше и сразу обновляет.'))
				]),
				statusBox
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Активные ноды')),
				nodesBox
			])
		]);

		return m.render().then(function(mapEl) {
			return E('div', {}, [ mapEl, extra ]);
		});
	}
});
