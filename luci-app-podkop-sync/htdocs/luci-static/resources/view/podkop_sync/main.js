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

/* scoped-стили: theme-agnostic (rgba-оверлеи + currentColor), работают в
   тёмной и светлой теме LuCI без знания её палитры. */
var PKS_CSS =
	'.pks-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:.4rem 0 .6rem}' +
	'.pks-tile{background:rgba(128,128,128,.12);border-radius:8px;padding:10px 14px}' +
	'.pks-tile .l{font-size:12px;opacity:.7}' +
	'.pks-tile .v{font-size:22px;font-weight:500;line-height:1.3}' +
	'.pks-cap{font-size:12px;opacity:.7;margin:0 0 1rem}' +
	'.pks-bar{display:flex;align-items:center;gap:10px;margin:.2rem 0 .5rem;flex-wrap:wrap}' +
	'.pks-bar .t{font-size:15px;font-weight:500}' +
	'.pks-pill{font-size:12px;opacity:.85;background:rgba(128,128,128,.15);border-radius:20px;padding:2px 9px}' +
	'.pks-flt{margin-left:auto}' +
	'.pks-wrap{border:1px solid rgba(128,128,128,.28);border-radius:8px;overflow:hidden}' +
	'.pks-scroll{max-height:360px;overflow:auto}' +
	'.pks-tbl{width:100%;border-collapse:collapse;font-size:13px}' +
	'.pks-tbl th{text-align:left;font-weight:500;opacity:.7;padding:9px 12px;border-bottom:1px solid rgba(128,128,128,.28)}' +
	'.pks-tbl td{padding:8px 12px;border-bottom:1px solid rgba(128,128,128,.16)}' +
	'.pks-tbl tr:nth-child(even) td{background:rgba(128,128,128,.06)}' +
	'.pks-r{text-align:right}' +
	'.pks-mono{font-family:monospace;opacity:.85}' +
	'.pks-chip{font-family:monospace;font-size:11px;opacity:.85;background:rgba(128,128,128,.15);border:1px solid rgba(128,128,128,.28);border-radius:4px;padding:1px 6px;white-space:nowrap}' +
	'.pks-dot{width:8px;height:8px;border-radius:50%;display:inline-block;vertical-align:middle;margin-right:7px}' +
	'.pks-set{margin-top:1.2rem;border-top:1px solid rgba(128,128,128,.22);padding-top:.3rem}' +
	'.pks-set>summary{cursor:pointer;font-size:15px;font-weight:500;padding:8px 0;list-style:none}' +
	'.pks-set>summary::-webkit-details-marker{display:none}' +
	'.pks-set>summary::before{content:"\\25B8\\00A0";opacity:.6}' +
	'.pks-set[open]>summary::before{content:"\\25BE\\00A0"}';

function pksTile(label, val) {
	return E('div', { 'class': 'pks-tile' }, [
		E('div', { 'class': 'l' }, label),
		E('div', { 'class': 'v' }, val)
	]);
}

function renderStatusInner(st) {
	st = st || {};
	var ok = (st.status === 'ok'), err = (st.status === 'error');
	var color = ok ? '#3fb950' : (err ? '#f85149' : '#8b949e');
	var label = ok ? _('OK') : (err ? _('Ошибка') : _('не запускалось'));

	return [
		E('div', { 'class': 'pks-tiles' }, [
			pksTile(_('Всего нод'), String(st.count || 0)),
			pksTile(_('Из подписки'), String(st.sub || 0)),
			pksTile(_('Вручную'), String(st.manual || 0)),
			E('div', { 'class': 'pks-tile' }, [
				E('div', { 'class': 'l' }, _('Статус')),
				E('div', { 'class': 'v', 'style': 'font-size:15px;display:flex;align-items:center;gap:7px' }, [
					E('span', { 'class': 'pks-dot', 'style': 'background:' + color }), label
				]),
				E('div', { 'style': 'font-size:11px;opacity:.7;margin-top:2px' }, fmtTime(st.last_update))
			])
		]),
		E('div', { 'class': 'pks-cap' }, [
			st.message ? String(st.message) + ' · ' : '',
			_('секция') + ' ' + String(st.section || 'main')
		])
	];
}

function renderNodesPanel(nodes) {
	nodes = Array.isArray(nodes) ? nodes : [];
	var tbody = E('tbody', {});
	nodes.forEach(function(link) {
		var n = parseVless(link);
		if (!n) return;
		var proto = n.proto.replace('VLESS · ', '');
		tbody.appendChild(E('tr', {}, [
			E('td', {}, [ E('span', { 'class': 'pks-dot', 'style': 'background:#3fb950' }), n.name ]),
			E('td', {}, E('span', { 'class': 'pks-chip' }, proto + ' · ' + n.net.toUpperCase())),
			E('td', { 'class': 'pks-mono' }, n.host),
			E('td', { 'class': 'pks-mono pks-r' }, n.port)
		]));
	});

	var cntPill = E('span', { 'class': 'pks-pill' }, String(tbody.children.length));
	var filter = E('input', {
		'type': 'text', 'class': 'cbi-input-text pks-flt',
		'placeholder': _('Фильтр по имени или хосту'),
		'style': 'width:230px;max-width:55%'
	});
	filter.addEventListener('input', function() {
		var q = this.value.trim().toLowerCase(), shown = 0;
		Array.prototype.forEach.call(tbody.children, function(tr) {
			var ok = tr.textContent.toLowerCase().indexOf(q) > -1;
			tr.style.display = ok ? '' : 'none';
			if (ok) shown++;
		});
		cntPill.textContent = String(shown);
	});

	var body = tbody.children.length
		? E('div', { 'class': 'pks-wrap' }, E('div', { 'class': 'pks-scroll' },
			E('table', { 'class': 'pks-tbl' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('Название')),
					E('th', {}, _('Протокол')),
					E('th', {}, _('Хост / IP')),
					E('th', { 'class': 'pks-r' }, _('Порт'))
				])),
				tbody
			])))
		: E('em', { 'style': 'opacity:.7' }, _('Нод пока нет — запустите обновление.'));

	return E('div', { 'id': 'podkop-nodes-panel' }, [
		E('div', { 'class': 'pks-bar' }, [
			E('span', { 'class': 't' }, _('Активные ноды')), cntPill, filter
		]),
		body
	]);
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
		/* без заголовка/описания у самой формы — свой компактный заголовок сверху,
		   а всю форму прячем в сворачиваемую секцию «Настройки» */
		var m = new form.Map('podkop_sub');

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
		var nodesBox = renderNodesPanel(status.nodes);

		function onSyncNow() {
			var self = this;
			/* Сохраняем форму в uci-сессию и ДОЖИДАЕМСЯ настоящего commit'а
			   (промис uci.apply() резолвится после записи в /etc/config), и только
			   потом синкаем — иначе sync читает старый конфиг (баг «со второго
			   раза»). uci.apply() зовём только при наличии изменений, иначе он
			   отвечает "code 5: No data received". После — освежаем бейдж. */
			return self.handleSave(null).then(function() {
				return uci.changes();
			}).then(function(ch) {
				var has = false, k;
				for (k in (ch || {})) {
					if (ch[k] && ch[k].length) { has = true; break; }
				}
				return has ? uci.apply() : null;
			}).then(function() {
				try { ui.changes.renderChangeIndicator(); } catch (e) {}
				ui.showModal(_('Обновление подписок…'), [
					E('p', { 'class': 'spinning' }, _('Скачивание и разбор, подождите…'))
				]);
				return callSync();
			}).then(function(res) {
				ui.hideModal();
				res = res || {};

				dom.content(statusBox, renderStatusInner(res));
				var newNodes = renderNodesPanel(res.nodes);
				var old = document.getElementById('podkop-nodes-panel');
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

		var extra = E('div', { 'class': 'cbi-section' }, [
			E('style', {}, PKS_CSS),
			E('h2', { 'style': 'margin:0 0 2px' }, 'Podkop Sync'),
			E('p', { 'class': 'pks-cap' },
				_('Скачивает подписки, разбирает в vless-ссылки и применяет к секции podkop (URLTest).')),
			E('p', {}, [
				E('button', {
					'class': 'btn cbi-button cbi-button-apply',
					'click': ui.createHandlerFn(this, onSyncNow)
				}, _('Обновить сейчас')),
				E('span', { 'style': 'margin-left:1em;opacity:.7' },
					_('Сохраняет настройки и сразу обновляет.'))
			]),
			statusBox,
			nodesBox
		]);

		return m.render().then(function(mapEl) {
			var settings = E('details', { 'class': 'pks-set' }, [
				E('summary', {}, _('Настройки')),
				mapEl
			]);
			return E('div', {}, [ extra, settings ]);
		});
	}
});
