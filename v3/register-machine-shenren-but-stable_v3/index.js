const path = require('path');
const fs = require('fs');
const { DDGEmailProvider } = require('./src/ddgProvider');
const { BrowserbaseService } = require('./src/browserbaseService');
const { OAuthService } = require('./src/oauthService');
const { TempForwardService } = require('./src/tempForwardService');
const { generateRandomName, generateRandomPassword } = require('./src/randomIdentity');
const config = require('./src/config');

// 目标生成数量
const TARGET_COUNT = parseInt(process.argv[2], 10) || 1;

function isMissionAccomplishedUrl(url) {
    return typeof url === 'string'
        && url.startsWith('data:text/html')
        && url.includes('MISSION_ACCOMPLISHED');
}

function isExpectedCallbackUrl(expectedCallbackUrl, currentUrl) {
    try {
        const expected = new URL(expectedCallbackUrl);
        const current = new URL(currentUrl);

        return current.protocol === expected.protocol
            && current.hostname === expected.hostname
            && current.port === expected.port
            && current.pathname === expected.pathname
            && (current.searchParams.has('code') || current.searchParams.has('error'));
    } catch (error) {
        return false;
    }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * 构建注入验证码的 JS 表达式
 */
function buildInjectionJS(code) {
    return `(function(code) {
        if (window.location.href.indexOf('email-verification') === -1) {
            return { success: false, reason: 'not_on_verification_page' };
        }
        var nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        function fill(el, val) {
            nativeSetter.call(el, val);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }
        // 策略1: 单输入框
        var selectors = [
            'input[name="code"]', 'input[name="otp"]',
            'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]',
            'input[type="text"][maxlength="6"]', 'input[data-testid*="otp"]',
            'input[data-testid*="code"]', 'input[aria-label*="code"]',
            'input[placeholder*="code"]', 'input[placeholder*="Code"]'
        ];
        for (var i = 0; i < selectors.length; i++) {
            var el = document.querySelector(selectors[i]);
            if (el && el.offsetParent !== null) {
                fill(el, code);
                setTimeout(function() {
                    var btns = document.querySelectorAll('button[type="submit"], button');
                    for (var j = 0; j < btns.length; j++) {
                        var t = btns[j].textContent.toLowerCase();
                        if (t.includes('continue') || t.includes('verify') || t.includes('submit')) { btns[j].click(); break; }
                    }
                }, 500);
                return { success: true, strategy: 'single-input', selector: selectors[i] };
            }
        }
        // 策略2: 多位单字符输入框
        var digitInputs = document.querySelectorAll('input[maxlength="1"]');
        if (digitInputs.length >= 6) {
            for (var k = 0; k < 6; k++) { fill(digitInputs[k], code[k]); }
            setTimeout(function() {
                var btns = document.querySelectorAll('button[type="submit"], button');
                for (var j = 0; j < btns.length; j++) {
                    var t = btns[j].textContent.toLowerCase();
                    if (t.includes('continue') || t.includes('verify') || t.includes('submit')) { btns[j].click(); break; }
                }
            }, 500);
            return { success: true, strategy: 'multi-input' };
        }
        // 策略3: 兜底 - 唯一可见空文本输入
        var visible = Array.from(document.querySelectorAll('input[type="text"], input:not([type])')).filter(function(e) { return e.offsetParent !== null && !e.value; });
        if (visible.length === 1) {
            fill(visible[0], code);
            return { success: true, strategy: 'fallback' };
        }
        return { success: false, reason: 'no_input_found', url: window.location.href };
    })('${code}')`;
}

/**
 * 在页面顶部注入视觉提示，让 Agent 截图时看到指引
 */
function buildVisualHintJS(message) {
    const escaped = message.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
    return `(function() {
        if (document.getElementById('__agent_hint__')) return false;
        var div = document.createElement('div');
        div.id = '__agent_hint__';
        div.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#ff0;color:#000;padding:16px;font-size:20px;font-weight:bold;text-align:center;border-bottom:3px solid #f00;';
        div.textContent = '${escaped}';
        document.body.prepend(div);
        return true;
    })()`;
}

/**
 * 构建预填登录表单的 JS 表达式
 */
function buildLoginFillJS(email, password) {
    return `(function(email, password) {
        var href = window.location.href;
        var isLoginPage = href.indexOf('/log-in') !== -1 || href.indexOf('/create-account') !== -1;
        if (!isLoginPage) {
            return { success: false, reason: 'not_on_login_page' };
        }
        var nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        function fill(el, val) {
            nativeSetter.call(el, val);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }
        var filled = [];
        // 邮箱
        var emailEl = document.querySelector('input[name="email"], input[type="email"], input[autocomplete="email"], input[autocomplete="username"]');
        if (emailEl && emailEl.offsetParent !== null && !emailEl.value) {
            fill(emailEl, email);
            filled.push('email');
        }
        // 密码
        var pwEl = document.querySelector('input[name="password"], input[type="password"]');
        if (pwEl && pwEl.offsetParent !== null && !pwEl.value) {
            fill(pwEl, password);
            filled.push('password');
        }
        if (filled.length === 0) {
            return { success: false, reason: 'no_empty_fields' };
        }
        // 点击提交
        setTimeout(function() {
            var btns = document.querySelectorAll('button[type="submit"], button');
            for (var j = 0; j < btns.length; j++) {
                var t = btns[j].textContent.toLowerCase();
                if (t.includes('continue') || t.includes('log in') || t.includes('sign in')
                    || t.includes('submit') || t.includes('next') || t.includes('登录')) {
                    btns[j].click(); break;
                }
            }
        }, 500);
        return { success: true, filled: filled };
    })('${email.replace(/'/g, "\\'")}', '${password.replace(/'/g, "\\'")}')`;
}

/**
 * 构建预填 about-you 页面（姓名+生日）的 JS 表达式
 */
function buildAboutYouFillJS(fullName, birthDate) {
    // birthDate 格式: YYYY-MM-DD → 转为 MM/DD/YYYY
    const parts = birthDate.split('-');
    const mmddyyyy = `${parts[1]}/${parts[2]}/${parts[0]}`;
    return `(function(name, birthday) {
        if (window.location.href.indexOf('/about-you') === -1) {
            return { success: false, reason: 'not_on_about_you_page' };
        }
        var nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        function fill(el, val) {
            nativeSetter.call(el, val);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }
        var filled = [];
        // 姓名
        var nameEl = document.querySelector('input[name="name"], input[name="fullName"], input[name="full_name"]');
        if (!nameEl) {
            var labels = document.querySelectorAll('label');
            for (var i = 0; i < labels.length; i++) {
                var t = labels[i].textContent.toLowerCase();
                if (t.includes('name') || t.includes('full name')) {
                    nameEl = labels[i].querySelector('input') || document.getElementById(labels[i].getAttribute('for'));
                    break;
                }
            }
        }
        if (!nameEl) {
            var inputs = document.querySelectorAll('input[type="text"], input:not([type])');
            for (var i = 0; i < inputs.length; i++) {
                if (inputs[i].offsetParent !== null && !inputs[i].value) { nameEl = inputs[i]; break; }
            }
        }
        if (nameEl && !nameEl.value) {
            fill(nameEl, name);
            filled.push('name');
        }
        // 生日
        var bdEl = document.querySelector('input[name="birthday"], input[name="birthdate"], input[name="birth_date"]');
        if (!bdEl) {
            var inputs = document.querySelectorAll('input');
            for (var i = 0; i < inputs.length; i++) {
                var ph = (inputs[i].placeholder || '').toLowerCase();
                var lb = (inputs[i].getAttribute('aria-label') || '').toLowerCase();
                if (ph.includes('birthday') || ph.includes('mm/dd') || lb.includes('birthday') || lb.includes('birth')) {
                    bdEl = inputs[i]; break;
                }
            }
        }
        if (bdEl && bdEl.value !== birthday) {
            fill(bdEl, birthday);
            filled.push('birthday');
        }
        if (filled.length === 0) {
            return { success: false, reason: 'no_empty_fields' };
        }
        setTimeout(function() {
            // 先处理可能的生日确认弹窗（OK/Cancel）
            var allBtns = document.querySelectorAll('button');
            for (var j = 0; j < allBtns.length; j++) {
                var t = allBtns[j].textContent.trim().toLowerCase();
                if (t === 'ok') { allBtns[j].click(); break; }
            }
            // 再点提交按钮
            setTimeout(function() {
                var btns = document.querySelectorAll('button[type="submit"], button');
                for (var j = 0; j < btns.length; j++) {
                    var t = btns[j].textContent.toLowerCase();
                    if (t.includes('finish') || t.includes('continue') || t.includes('create')) {
                        btns[j].click(); break;
                    }
                }
            }, 500);
        }, 500);
        return { success: true, filled: filled };
    })('${fullName.replace(/'/g, "\\'")}', '${mmddyyyy}')`;
}

/**
 * 持续尝试预填登录表单（后台运行直到 abort）
 * about-you 页面交给 Agent 原始 Goal 处理
 */
function startFormFill(browserbase, phaseLabel, email, password, abortController) {
    return (async () => {
        while (!abortController.signal.aborted) {
            try {
                const loginResult = await browserbase.evaluateOnPage(buildLoginFillJS(email, password));
                if (loginResult && loginResult.success) {
                    console.log(`[${phaseLabel}] 登录表单预填成功: ${loginResult.filled.join(', ')}`);
                }
            } catch (_) {}
            await sleep(3000);
        }
    })();
}

/**
 * 通过 CDP 注入验证码（带重试）
 */
async function injectVerificationCode(browserbase, code, options = {}) {
    const { maxRetries = 20, retryInterval = 3000, signal } = options;
    const js = buildInjectionJS(code);

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        if (signal && signal.aborted) return { success: false, reason: 'aborted' };

        try {
            const result = await browserbase.evaluateOnPage(js);
            if (result && result.success) return result;
        } catch (_) {}

        await sleep(retryInterval);
    }

    return { success: false, reason: 'max_retries_exceeded' };
}

/**
 * 事件驱动的验证码获取与注入
 * 返回 { trigger, promise }：
 *   - trigger(): 由 onUrlChange 在检测到 email-verification 时调用
 *   - promise: 后台任务 promise，用于 Promise.allSettled
 */
function startCodeInjection(browserbase, phaseLabel, abortController) {
    const tempForward = new TempForwardService(config.tempForwardToken);
    let round = 0;
    let lastCodeTimestamp = Date.now();
    let gateResolve = null;

    const trigger = () => {
        if (gateResolve) {
            gateResolve();
            gateResolve = null;
        }
    };

    const promise = (async () => {
        while (!abortController.signal.aborted) {
            // 等待 email-verification 页面触发
            await new Promise(resolve => {
                gateResolve = resolve;
                abortController.signal.addEventListener('abort', resolve, { once: true });
            });
            if (abortController.signal.aborted) return;

            round++;
            try {
                console.log(`[${phaseLabel}] 检测到验证码页面，开始获取验证码 (第${round}轮)...`);
                const code = await tempForward.pollForCode({
                    fromAddress: 'noreply@tm.openai.com',
                    sinceTimestamp: lastCodeTimestamp,
                    interval: 3000,
                    timeout: 120000,
                    signal: abortController.signal
                });

                lastCodeTimestamp = Date.now();
                console.log(`[${phaseLabel}] 获取到验证码: ${code} (第${round}轮)`);

                const result = await injectVerificationCode(browserbase, code, {
                    maxRetries: 20,
                    retryInterval: 3000,
                    signal: abortController.signal
                });

                if (result.success) {
                    console.log(`[${phaseLabel}] 验证码注入成功 (策略: ${result.strategy})`);
                } else {
                    let currentUrl = '';
                    try { currentUrl = await browserbase.evaluateOnPage('window.location.href') || ''; } catch (_) {}
                    if (currentUrl.includes('email-verification')) {
                        console.warn(`[${phaseLabel}] CDP 注入失败: ${result.reason}，启用 Agent 回退`);
                        try {
                            await browserbase.sendAgentGoal(`验证码是 ${code}，请将它填入验证码输入框并提交。`);
                        } catch (e) {
                            console.error(`[${phaseLabel}] 回退 Agent 任务失败: ${e.message}`);
                        }
                    } else {
                        console.log(`[${phaseLabel}] 页面已离开验证页，跳过 Agent 回退`);
                    }
                }
            } catch (error) {
                if (error.name === 'AbortError' || abortController.signal.aborted) return;
                console.error(`[${phaseLabel}] 验证码获取失败: ${error.message}，等待下次触发`);
            }
            // 回到循环顶部，等待下一次 email-verification 触发
        }
    })();

    return { trigger, promise };
}

/**
 * 生成随机用户数据
 */
function generateUserData() {
    const fullName = generateRandomName();
    const password = generateRandomPassword();
    
    // 生成出生日期 (25-40岁)
    const age = 25 + Math.floor(Math.random() * 16);
    const birthYear = new Date().getFullYear() - age;
    const birthMonth = 1 + Math.floor(Math.random() * 12);
    const birthDay = 1 + Math.floor(Math.random() * 28);
    const birthDate = `${birthYear}-${String(birthMonth).padStart(2, '0')}-${String(birthDay).padStart(2, '0')}`;
    
    return {
        fullName,
        password,
        age,
        birthDate,
        birthMonth,
        birthDay,
        birthYear
    };
}

/**
 * 第一阶段：ChatGPT 注册
 */
async function phase1(emailProvider, browserbase, userData) {
    console.log('\n=========================================');
    console.log('[阶段1] 开始 ChatGPT 注册流程');
    console.log('=========================================');

    // 创建会话
    const session = await browserbase.createSession();

    // 构建 Agent Goal，根据是否支持本地验证码获取调整指令
    const localCodeEnabled = !!config.tempForwardToken;
    const verifyStep = localCodeEnabled
        ? '4. 验证码页面：验证码会被自动填入和提交，你只需等页面自动跳转即可'
        : `4. 验证码页面：在 ${config.mailInboxUrl} 上查收验证码并填入`;
    const goal = `请完成以下ChatGPT注册流程，每步操作后不要等待超过3秒：

1. 打开 https://chatgpt.com 并点击注册（Sign up）
2. 输入邮箱 ${emailProvider.getEmail()} 并继续
3. 输入密码 ${userData.password} 并继续
${verifyStep}
5. 个人信息页面：全名填 ${userData.fullName}，生日填 ${userData.birthDate}（如果要求年龄则换算），然后点击完成创建
6. 遇到要求添加手机号的页面，点Skip或跳过
7. 遇到"What brings you to ChatGPT"引导页，点Skip
8. 注册完成后不需要做其他操作`;

    console.log('[阶段1] Agent Goal 已准备');

    // 发送 Agent 任务，等待 HTTP 流建立后再连 CDP
    try {
        await browserbase.sendAgentGoal(goal);
    } catch (e) {
        console.error(`[阶段1] Agent 任务流异常: ${e.message}`);
    }

    const wsUrl = session.wsUrl;
    if (!wsUrl) {
        throw new Error('无法从 sessionUrl 中提取 WSS 地址');
    }

    const abortController = new AbortController();

    console.log('[阶段1] 开始监控页面 URL 变化...');

    // 并行：登录 + about-you 表单预填
    const loginFillPromise = startFormFill(browserbase, '阶段1', emailProvider.getEmail(), userData.password, abortController);

    // 事件驱动：验证码获取+注入（仅在本地邮件服务可用时启用）
    const codeInjection = localCodeEnabled ? startCodeInjection(browserbase, '阶段1', abortController) : null;
    if (!localCodeEnabled) console.log('[阶段1] 本地验证码获取不可用，由 Agent 处理验证码');

    // 并行：CDP URL 监控
    let seenAboutYou = false;
    const cdpPromise = browserbase.connectToCDP(wsUrl, {
        targetLabel: '注册完成',
        targetMatcher: (url) => {
            if (url.includes('/about-you')) seenAboutYou = true;
            return isMissionAccomplishedUrl(url) || (seenAboutYou && /^https:\/\/chatgpt\.com\/?(\?.*)?$/.test(url));
        },
        rejectMatcher: (url) => url.includes('/add-phone'),
        rejectMessage: '检测到手机验证页面 (add-phone)，放弃当前注册',
        onUrlChange: (url) => {
            console.log(`[阶段1] URL 变化: ${url}`);
            if (url.includes('email-verification') && codeInjection) codeInjection.trigger();
            if (url.includes('/about-you')) {
                const hint = `INSTRUCTION: Fill "Full name" with "${userData.fullName}", set "Birthday" to "${userData.birthDate}" (use MM/DD/YYYY format), then click "Finish creating account".`;
                browserbase.evaluateOnPage(buildVisualHintJS(hint)).then(injected => {
                    if (injected) console.log(`[阶段1] 已注入 about-you 页面提示`);
                }).catch(() => {});
            }
        },
        onTargetReached: (url) => {
            console.log(`[阶段1] 注册流程完成！(${url.substring(0, 40)})`);
            abortController.abort();
            return url;
        },
        timeout: 1800000
    });
    cdpPromise.catch(() => abortController.abort());

    const promises = [cdpPromise, loginFillPromise];
    if (codeInjection) promises.push(codeInjection.promise);
    const [cdpResult] = await Promise.allSettled(promises);

    if (cdpResult.status === 'rejected') {
        throw cdpResult.reason;
    }

    const finalUrl = cdpResult.value;
    console.log(`[阶段1] 注册完成！`);
    browserbase.disconnect();

    return true;
}

/**
 * 第二阶段：Codex OAuth 授权
 */
async function phase2(emailProvider, browserbase, oauthService, userData) {
    console.log('\n=========================================');
    console.log('[阶段2] 开始 Codex OAuth 授权流程');
    console.log('=========================================');

    // 重新生成 PKCE 参数
    oauthService.regeneratePKCE();

    // 获取 OAuth URL
    const authUrl = oauthService.getAuthUrl();
    console.log(`[阶段2] OAuth URL: ${authUrl.substring(0, 100)}...`);

    // 创建新的会话
    const session = await browserbase.createSession();

    // 构建 Agent Goal
    const localCodeEnabled = !!config.tempForwardToken;
    const verifyStep = localCodeEnabled
        ? '4. 验证码页面：验证码会被自动填入和提交，你只需等页面自动跳转即可'
        : `4. 验证码页面：在 ${config.mailInboxUrl} 上查收验证码并填入`;
    const goal = `请完成以下登录流程，每步操作后不要等待超过3秒：

1. 导航到 ${authUrl}
2. 输入邮箱 ${emailProvider.getEmail()} 并继续
3. 输入密码 ${userData.password} 并继续
${verifyStep}
5. 遇到要求添加手机号的页面，点Skip或跳过
6. 看到Codex授权页面，点击允许/同意登录
7. 页面跳转到localhost后不需要做其他操作`;

    console.log('[阶段2] Agent Goal 已准备');

    // 发送 Agent 任务，等待 HTTP 流建立后再连 CDP
    try {
        await browserbase.sendAgentGoal(goal);
    } catch (e) {
        console.error(`[阶段2] Agent 任务流异常: ${e.message}`);
    }

    const wsUrl = session.wsUrl;
    if (!wsUrl) {
        throw new Error('无法从 sessionUrl 中提取 WSS 地址');
    }

    const abortController = new AbortController();

    console.log('[阶段2] 开始监控页面 URL 变化，等待 localhost 回调...');

    // 并行：登录表单预填
    const loginFillPromise = startFormFill(browserbase, '阶段2', emailProvider.getEmail(), userData.password, abortController);

    // 事件驱动：验证码获取+注入（仅在本地邮件服务可用时启用）
    const codeInjection = localCodeEnabled ? startCodeInjection(browserbase, '阶段2', abortController) : null;
    if (!localCodeEnabled) console.log('[阶段2] 本地验证码获取不可用，由 Agent 处理验证码');

    // 并行：CDP URL 监控（遇到 add-phone 立即放弃）
    const cdpPromise = browserbase.connectToCDP(wsUrl, {
        targetLabel: 'localhost 回调',
        targetMatcher: (url) => isExpectedCallbackUrl(oauthService.redirectUri, url),
        rejectMatcher: (url) => url.includes('/add-phone'),
        rejectMessage: '检测到手机验证页面 (add-phone)，放弃当前授权',
        onUrlChange: (url) => {
            console.log(`[阶段2] URL 变化: ${url}`);
            if (url.includes('email-verification') && codeInjection) codeInjection.trigger();
        },
        onTargetReached: (url) => {
            console.log(`[阶段2] 检测到 localhost 回调！`);
            abortController.abort();
            return url;
        },
        timeout: 1800000
    });
    cdpPromise.catch(() => abortController.abort());

    const promises = [cdpPromise, loginFillPromise];
    if (codeInjection) promises.push(codeInjection.promise);
    const [cdpResult] = await Promise.allSettled(promises);

    if (cdpResult.status === 'rejected') {
        throw cdpResult.reason;
    }

    const callbackUrl = cdpResult.value;
    console.log(`[阶段2] 回调 URL: ${callbackUrl}`);

    // 提取授权参数
    const params = oauthService.extractCallbackParams(callbackUrl);
    if (!params || params.error) {
        throw new Error(`OAuth 授权失败: ${params?.error_description || params?.error || '未知错误'}`);
    }

    if (!params.code) {
        throw new Error('回调 URL 中未找到授权码');
    }

    console.log(`[阶段2] 成功获取授权码: ${params.code.substring(0, 10)}...`);

    // 用授权码换取 Token
    const tokenData = await oauthService.exchangeTokenAndSave(params.code, emailProvider.getEmail());

    browserbase.disconnect();

    return tokenData;
}

/**
 * 单次注册流程
 */
async function runSingleRegistration() {
    console.log('\n=========================================');
    console.log('[主程序] 开始一次全新的注册与授权流程');
    console.log('=========================================');
    
    const emailProvider = new DDGEmailProvider();
    const browserbase = new BrowserbaseService();
    const oauthService = new OAuthService();
    
    try {
        // 0. 生成用户数据
        const userData = generateUserData();
        console.log(`[主程序] 用户数据已生成:`);
        console.log(`  - 姓名: ${userData.fullName}`);
        console.log(`  - 年龄: ${userData.age}`);
        console.log(`  - 出生日期: ${userData.birthDate}`);
        
        // 1. 生成邮箱别名
        await emailProvider.generateAlias();
        
        // 2. 第一阶段：ChatGPT 注册
        await phase1(emailProvider, browserbase, userData);
        
        // 3. 第二阶段：Codex OAuth 授权
        const tokenData = await phase2(emailProvider, browserbase, oauthService, userData);
        
        console.log('[主程序] 本次注册流程圆满结束！');
        console.log(`[主程序] Token 已保存，邮箱: ${tokenData.email}`);
        
        return true;
        
    } catch (error) {
        console.error('[主程序] 本次任务执行失败:', error.message);
        throw error;
    } finally {
        browserbase.disconnect();
    }
}

/**
 * 检查 token 数量
 */
async function checkTokenCount() {
    const outputDir = path.join(process.cwd(), 'tokens');
    if (!fs.existsSync(outputDir)) {
        return 0;
    }
    const files = fs.readdirSync(outputDir).filter(f => f.startsWith('token_') && f.endsWith('.json'));
    return files.length;
}

/**
 * 归档已有 tokens
 */
function archiveExistingTokens() {
    const outputDir = path.join(process.cwd(), 'tokens');
    if (!fs.existsSync(outputDir)) return;
    
    const files = fs.readdirSync(outputDir).filter(f => f.startsWith('token_') && f.endsWith('.json'));
    for (const file of files) {
        const oldPath = path.join(outputDir, file);
        const newPath = path.join(outputDir, `old_${file}`);
        fs.renameSync(oldPath, newPath);
        console.log(`[归档] ${file} → old_${file}`);
    }
}

/**
 * 启动批量注册
 */
async function startBatch() {
    console.log(`[启动] 开始执行 Codex 远程注册机，目标生成数量: ${TARGET_COUNT}`);
    
    // 检查配置
    if (!config.ddgToken) {
        console.error('[错误] 未配置 ddgToken，请检查 config.json 文件');
        process.exit(1);
    }
    if (!config.mailInboxUrl) {
        console.error('[错误] 未配置 mailInboxUrl，请检查 config.json 文件');
        process.exit(1);
    }
    
    // 归档已有的 token 文件
    archiveExistingTokens();
    
    while (true) {
        const currentCount = await checkTokenCount();
        if (currentCount >= TARGET_COUNT) {
            console.log(`\n[完成] 当前 Token 文件数量 (${currentCount}) 已达到目标 (${TARGET_COUNT})。程序退出。`);
            break;
        }
        
        console.log(`\n[进度] 目前 Token 数量 ${currentCount} / 目标 ${TARGET_COUNT}`);
        
        try {
            await runSingleRegistration();
        } catch (error) {
            console.error('[主程序] 注册失败，准备重试...');
        }
    }
}

startBatch().catch(console.error);
