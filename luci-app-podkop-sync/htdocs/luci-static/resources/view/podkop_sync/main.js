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

/* ВАЖНО: данные из подписки и статуса передаём в E() только МАССИВОМ детей.
   Строка третьим аргументом уходит в innerHTML, и имя/хост ноды из чужой
   подписки исполнились бы как HTML в сессии администратора (XSS). */

/* Разбор vless:// ссылки для таблицы (имя/протокол/сеть/хост/порт).
   Полностью percent-encoded фрагмент декодируется здесь. */
function parseVless(link) {
	/* хост не содержит «:» — иначе «:цифры» в имени ноды принимались бы за порт */
	var m = /^vless:\/\/([^@]+)@([^:\/?#]+):(\d+)\/?(?:\?([^#]*))?(?:#(.*))?$/i.exec(link);
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
	'.pks-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin:.2rem 0 1.1rem}' +
	/* Заголовок и значок версии центрируются обычным flex. Чтобы середина считалась
	   по строчным буквам заголовка (их большинство, глаз видит центр там), строка
	   заголовка обрезается по их высоте (text-box). Браузер без поддержки свойства
	   просто проигнорирует его и отцентрирует по строке. min-height возвращает заголовку
	   высоту обычной строки, чтобы буквы не выступали за его границы. */
	'.pks-head h2{margin:0;padding:0;min-height:1.2em;display:flex;align-items:center;gap:10px}' +
	'.pks-title{display:block;line-height:1.2;text-box:trim-both ex alphabetic}' +
	'.pks-ver{font-size:12px;font-weight:400;line-height:1;color:#fff;background:tomato;border:1px solid tomato;border-radius:5px;padding:3px 6px;white-space:nowrap}' +
	'.pks-card{border:1px solid rgba(128,128,128,.2);border-radius:10px;background:rgba(128,128,128,.04);padding:14px 16px;margin:0 0 14px}' +
	'.pks-card>.pks-bar{border-bottom:1px solid rgba(128,128,128,.2);padding-bottom:10px;margin:0 0 4px}' +
	'.pks-card .pks-tiles{margin:0 0 .5rem}' +
	'.pks-card>.pks-cap:last-child{margin:0}' +
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
	'.pks-set[open]>summary::before{content:"\\25BE\\00A0"}' +
	/* мягкая стилизация нативной формы CBI — только внутри .pks-set */
	'.pks-form .cbi-section-node{background:rgba(128,128,128,.06);border:1px solid rgba(128,128,128,.2);border-radius:8px;padding:2px 14px;margin-top:.4rem}' +
	'.pks-form .cbi-value{padding:12px 2px;border-bottom:1px solid rgba(128,128,128,.14);margin:0}' +
	'.pks-form .cbi-section-node>div:last-child .cbi-value,.pks-form .cbi-value:last-child{border-bottom:0}' +
	'.pks-form .cbi-value-title{font-weight:500;opacity:.9}' +
	'.pks-form .cbi-value-description{font-size:12px;opacity:.65;margin-top:5px}' +
	'.pks-form input.cbi-input-text,.pks-form select.cbi-input-select,.pks-form textarea.cbi-input-textarea{border-radius:6px}' +
	'.pks-form input.cbi-input-text{max-width:440px}' +
	'.pks-form .cbi-button-add{border-radius:6px}' +
	'.pks-form .cbi-dynlist .btn{margin-left:8px}' +
	'.pks-form .cbi-section{margin:0 0 1rem}' +
	'.pks-form .cbi-section>h3{font-size:12px;font-weight:500;opacity:.55;text-transform:uppercase;letter-spacing:.6px;margin:1rem 0 .3rem}' +
	'.pks-form .cbi-section:first-of-type>h3{margin-top:.3rem}';

function pksTile(label, val) {
	return E('div', { 'class': 'pks-tile' }, [
		E('div', { 'class': 'l' }, [ label ]),
		E('div', { 'class': 'v' }, [ String(val) ])
	]);
}

function renderStatusInner(st) {
	st = st || {};
	var ok = (st.status === 'ok'), err = (st.status === 'error'), warn = (st.status === 'warn');
	var color = ok ? '#3fb950' : (err ? '#f85149' : (warn ? '#d29922' : '#8b949e'));
	var label = ok ? _('OK') : (err ? _('Ошибка') : (warn ? _('Внимание') : _('не запускалось')));

	return [
		E('div', { 'class': 'pks-tiles' }, [
			pksTile(_('Всего нод'), String(st.count || 0)),
			pksTile(_('Из подписки'), String(st.sub || 0)),
			pksTile(_('Вручную'), String(st.manual || 0)),
			E('div', { 'class': 'pks-tile' }, [
				E('div', { 'class': 'l' }, [ _('Статус') ]),
				E('div', { 'class': 'v', 'style': 'font-size:15px;display:flex;align-items:center;gap:7px' }, [
					E('span', { 'class': 'pks-dot', 'style': 'background:' + color }), label
				]),
				E('div', { 'style': 'font-size:11px;opacity:.7;margin-top:2px' }, [ String(fmtTime(st.last_update)) ])
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
			E('td', {}, [ E('span', { 'class': 'pks-chip' }, [ proto + ' · ' + String(n.net).toUpperCase() ]) ]),
			E('td', { 'class': 'pks-mono' }, [ String(n.host) ]),
			E('td', { 'class': 'pks-mono pks-r' }, [ String(n.port) ])
		]));
	});

	var cntPill = E('span', { 'class': 'pks-pill' }, [ String(tbody.children.length) ]);
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
		? E('div', { 'class': 'pks-scroll' },
			E('table', { 'class': 'pks-tbl' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('Название')),
					E('th', {}, _('Протокол')),
					E('th', {}, _('Хост / IP')),
					E('th', { 'class': 'pks-r' }, _('Порт'))
				])),
				tbody
			]))
		: E('em', { 'style': 'opacity:.7' }, _('Нод пока нет — запустите обновление.'));

	return E('div', { 'id': 'podkop-nodes-panel', 'class': 'pks-card' }, [
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
			/* podkop может быть не установлен — тогда его конфига нет; страница
			   всё равно должна открыться и сказать об этом */
			uci.load('podkop').catch(function() { return null; }),
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
		var o, s;

		/* карта 1 — «Источники нод»: видима, над таблицей (ввёл ссылку → сразу
		   ниже видишь ноды). Форма из двух карт одного конфига; Save & Apply
		   сохраняет обе. */
		var mSrc = new form.Map('podkop_sub');
		s = mSrc.section(form.NamedSection, 'config', 'podkop_sub', _('Источники нод'));
		s.anonymous = true;

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

		/* карта 2 — прочие настройки (в сворачиваемом блоке ниже таблицы) */
		var mSet = new form.Map('podkop_sub');

		s = mSet.section(form.NamedSection, 'config', 'podkop_sub', _('Применение'));
		s.anonymous = true;

		o = s.option(form.ListValue, 'section', _('Целевая секция Podkop'),
			_('Ноды пишутся в urltest_proxy_links выбранной секции. ' +
			  'Работают только секции в режиме URLTest.'));
		if (sections.length === 0) o.value('main', 'main');
		sections.forEach(function(sec) {
			var t = uci.get('podkop', sec, 'proxy_config_type') || '';
			o.value(sec, (t && t !== 'urltest') ? (sec + ' — ' + t + ' (не URLTest)') : sec);
		});
		o.default = 'main';

		o = s.option(form.Flag, 'deduplicate', _('Удалять дубликаты серверов'));
		o.default = '1';

		o = s.option(form.Flag, 'sticky', _('Не менять SNI и short id у работающих нод'),
			_('Панели вроде 3x-ui при каждом скачивании подписки выдают случайные SNI и ' +
			  'short id из списков ноды. Вкл — у ноды, которая сейчас работает, они ' +
			  'остаются прежними, и podkop не перезапускается без нужды; у неработающей ' +
			  'берутся свежие из подписки. Нужен включённый YACD в настройках podkop.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Flag, 'preserve_manual', _('Сохранять внешние ноды'),
			_('Сохранять ноды, добавленные в секцию напрямую в podkop (не через ' +
			  'поле выше). Выкл — секция = только ручные ноды из поля + подписка.'));
		o.default = '1';
		o.rmempty = false;

		s = mSet.section(form.NamedSection, 'config', 'podkop_sub', _('Автообновление'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Включить сервис'),
			_('Когда выключено — автообновление по расписанию отключено ' +
			  '(ручное «Обновить сейчас» продолжает работать).'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.ListValue, 'cron', _('Расписание'),
			_('Запускает синхронизацию автоматически через cron.'));
		o.value('0', _('Выключено'));
		o.value('6', _('Каждые 6 часов'));
		o.value('12', _('Каждые 12 часов'));
		o.value('24', _('Раз в сутки'));
		o.default = '24';

		s = mSet.section(form.NamedSection, 'config', 'podkop_sub', _('Сеть'));
		s.anonymous = true;

		o = s.option(form.Value, 'user_agent', _('User-Agent'),
			_('Отправляется curl при скачивании подписок. Пресеты дают Xray/base64, ' +
			  'который понимает парсер; можно вписать и свой.'));
		o.value('v2rayNG/1.9.5', 'v2rayNG/1.9.5');
		o.value('Happ/1.60.0', 'Happ/1.60.0');
		o.value('v2rayN/7.0', 'v2rayN/7.0');
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
					E('p', { 'class': 'spinning', 'id': 'pks-sync-note' }, _('Скачивание и разбор, подождите…'))
				]);
				return callSync();
			}).then(function(res) {
				/* Синхронизация идёт на роутере отдельным процессом. Если она не успела
				   за первые секунды (проверка конфига, перезапуск podkop — это до минуты),
				   бэкенд отвечает running:true, и мы опрашиваем статус, пока она не
				   закончится. Каждый запрос короткий, поэтому таймаут LuCI не срабатывает.
				   Во время перезапуска podkop отдельные запросы могут не пройти — это не
				   ошибка, просто спрашиваем ещё раз. */
				function waitFinish(res, left) {
					if (!res || !res.running || left <= 0)
						return res;
					dom.content(document.getElementById('pks-sync-note'),
						_('Проверка и применение нового списка, podkop может перезапускаться. Обычно до минуты…'));
					return new Promise(function(resolve) { window.setTimeout(resolve, 3000); })
						.then(function() { return callStatus().catch(function() { return { running: true }; }); })
						.then(function(st) { return waitFinish(st, left - 1); });
				}
				return waitFinish(res || {}, 60);
			}).then(function(res) {
				ui.hideModal();
				res = res || {};

				dom.content(statusBox, renderStatusInner(res));
				var newNodes = renderNodesPanel(res.nodes);
				var old = document.getElementById('podkop-nodes-panel');
				if (old && old.parentNode) old.parentNode.replaceChild(newNodes, old);

				if (res.running)
					ui.addNotification(null, E('p', {}, [ _('Синхронизация всё ещё выполняется. Обновите страницу через минуту, чтобы увидеть результат.') ]), 'info');
				else if (res.status === 'ok')
					ui.addNotification(null, E('p', {}, [ String(res.message || _('Обновлено: %s нод.').format(res.count || 0)) ]), 'info');
				else
					ui.addNotification(null, E('p', {}, [ String(res.message || _('Обновление не удалось.')) ]), 'danger');
			}).catch(function(e) {
				ui.hideModal();
				ui.addNotification(null, E('p', {}, [ _('Обновление не удалось') + ': ' + e ]), 'danger');
			});
		}

		var extra = E('div', { 'class': 'cbi-section' }, [
			E('style', {}, PKS_CSS),
			E('div', { 'class': 'pks-head' }, [
				E('div', {}, [
					E('h2', {}, [
						E('span', { 'class': 'pks-title' }, [ 'Podkop Sync' ]),
						status.version ? E('span', { 'class': 'pks-ver', 'title': _('Версия плагина') }, [ 'v' + String(status.version) ]) : ''
					]),
					E('div', { 'class': 'pks-cap', 'style': 'margin:2px 0 0' },
						_('Подписки и ручные ноды → секция podkop (URLTest).'))
				]),
				E('button', {
					'class': 'btn cbi-button cbi-button-apply',
					'style': 'flex:none',
					'title': _('Сохраняет настройки и сразу обновляет'),
					'click': ui.createHandlerFn(this, onSyncNow)
				}, _('Обновить сейчас'))
			]),
			(status.podkop === false) ? E('div', { 'class': 'alert-message warning' }, [
				_('Podkop не установлен: синхронизация не работает, ноды записывать некуда. ' +
				  'Установите Podkop и обновите страницу.')
			]) : '',
			E('div', { 'class': 'pks-card' }, statusBox)
		]);

		return Promise.all([ mSrc.render(), mSet.render() ]).then(function(maps) {
			var srcCard = E('div', { 'class': 'pks-form', 'style': 'margin-bottom:1rem' },
				[ maps[0] ]);
			var settings = E('details', { 'class': 'pks-set pks-form' }, [
				E('summary', {}, _('Настройки')),
				maps[1]
			]);
			/* порядок: заголовок+статус → источники+кнопка → таблица нод → настройки */
			return E('div', {}, [ extra, srcCard, nodesBox, settings ]);
		});
	}
});
