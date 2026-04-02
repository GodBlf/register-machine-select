const axios = require('axios');

class TempForwardService {
    constructor(token) {
        this.token = token;
        this.apiBase = 'https://tempforward.com/api/tempmail';
    }

    async fetchInbox() {
        try {
            const resp = await axios.get(`${this.apiBase}/inbox?token=${this.token}`);
            return resp.data.emails || [];
        } catch (error) {
            console.error('[TempForward] 获取收件箱失败:', error.message);
            return [];
        }
    }

    extractCode(subject) {
        const match = subject && subject.match(/(\d{6})/);
        return match ? match[1] : null;
    }

    async pollForCode(options = {}) {
        const {
            fromAddress = 'noreply@tm.openai.com',
            sinceTimestamp = Date.now(),
            interval = 5000,
            timeout = 180000,
            signal
        } = options;

        const deadline = Date.now() + timeout;

        while (Date.now() < deadline) {
            if (signal && signal.aborted) {
                const err = new Error('验证码轮询已取消');
                err.name = 'AbortError';
                throw err;
            }

            const emails = await this.fetchInbox();
            const matched = emails
                .filter(e =>
                    e.from_address === fromAddress &&
                    new Date(e.created_at).getTime() > sinceTimestamp
                )
                .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

            if (matched.length > 0) {
                const code = this.extractCode(matched[0].subject);
                if (code) {
                    return code;
                }
            }

            await new Promise((resolve, reject) => {
                const timer = setTimeout(resolve, interval);
                if (signal) {
                    signal.addEventListener('abort', () => {
                        clearTimeout(timer);
                        const err = new Error('验证码轮询已取消');
                        err.name = 'AbortError';
                        reject(err);
                    }, { once: true });
                }
            });
        }

        throw new Error('验证码获取超时');
    }
}

module.exports = { TempForwardService };
