import BizError from "../error/biz-error";
import orm from "../entity/orm";
import {oauth} from "../entity/oauth";
import { eq, inArray } from 'drizzle-orm';
import userService from "./user-service";
import loginService from "./login-service";
import cryptoUtils from "../utils/crypto-utils";
import roleService from "./role-service";

const oauthService = {

	async bindUser(c, params) {

		const { email, oauthUserId, code } = params;

		const oauthRow = await this.getById(c, oauthUserId);

		let userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (userRow) {
			throw new BizError('用户已绑定有邮箱')
		}

		await loginService.register(c, { email, password: cryptoUtils.genRandomPwd(), code }, true);

		userRow = await userService.selectByEmail(c, email);

		orm(c).update(oauth).set({ userId: userRow.userId }).where(eq(oauth.oauthUserId, oauthUserId)).run();
		const jwtToken = await loginService.login(c, { email, password: null }, true);

		return { userInfo: oauthRow, token: jwtToken}
	},

	async linuxDoLogin(c, params) {

		const { code } = params;

		let token = '';
		let userInfo = {}

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', c.env.linuxdo_client_id)
		reqParams.append('client_secret', c.env.linuxdo_client_secret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', c.env.linuxdo_callback_url)
		reqParams.append('grant_type', 'authorization_code')

		const tokenRes = await fetch("https://connect.linux.do/oauth2/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		})

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText)
		}

		token = await tokenRes.json()

		const userRes = await fetch('https://connect.linux.do/api/user', {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText)
		}

		userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.id);
		userInfo.active = userInfo.active ? 0 : 1;
		userInfo.silenced = userInfo.active ? 0 : 1;
		userInfo.trustLevel = userInfo.trust_level;
		userInfo.avatar = userInfo.avatar_url;

		const  oauthRow = await this.saveUser(c, userInfo);
		const userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (!userRow) {
			return { userInfo: oauthRow, token: null }
		}

		const JwtToken = await loginService.login(c, { email: userRow.email, password: null }, true);
		return { userInfo: oauthRow, token: JwtToken }
	},

	async oidcLogin(c, params) {
		const { code, codeVerifier } = params;
		if (!code) {
			throw new BizError('OIDC授权码不能为空');
		}

		const oidcConfig = this.getOidcConfig(c);
		const token = await this.exchangeOidcCode(c, oidcConfig, code, codeVerifier);
		const idTokenClaims = token.id_token ? this.decodeJwtPayload(token.id_token) : {};
		const userInfo = await this.getOidcUserInfo(c, oidcConfig, token.access_token, idTokenClaims);
		const email = String(userInfo.email || idTokenClaims.email || '').trim();
		if (!email) {
			throw new BizError('OIDC未返回邮箱');
		}

		const roleRow = await this.resolveOidcRole(c, userInfo, idTokenClaims);
		let userRow = await userService.selectByEmailIncludeDel(c, email);

		if (!userRow) {
			await loginService.register(c, {
				email,
				password: cryptoUtils.genRandomPwd(),
				roleId: roleRow.roleId
			}, true);
			userRow = await userService.selectByEmail(c, email);
		} else if (Number(userRow.isDel) === 0 && userRow.email !== c.env.admin && userRow.type !== roleRow.roleId) {
			await userService.setType(c, { userId: userRow.userId, type: roleRow.roleId });
			userRow.type = roleRow.roleId;
		}

		const oauthRow = await this.saveUser(c, {
			oauthUserId: this.buildOidcUserId(oidcConfig.issuer, userInfo.sub || idTokenClaims.sub || email),
			username: userInfo.preferred_username || userInfo.username || idTokenClaims.preferred_username || email,
			name: userInfo.name || idTokenClaims.name || email,
			avatar: userInfo.picture || idTokenClaims.picture || '',
			active: 0,
			trustLevel: 0,
			silenced: 0,
			userId: userRow.userId
		});

		const jwtToken = await loginService.login(c, { email: userRow.email, password: null }, true);
		return { userInfo: oauthRow, token: jwtToken };
	},

	getOidcConfig(c) {
		const issuer = String(c.env.oidc_issuer || '').trim().replace(/\/+$/, '');
		if (!issuer) {
			throw new BizError('缺少OIDC配置: oidc_issuer');
		}
		if (!c.env.oidc_client_id) {
			throw new BizError('缺少OIDC配置: oidc_client_id');
		}
		if (!c.env.oidc_callback_url) {
			throw new BizError('缺少OIDC配置: oidc_callback_url');
		}

		return {
			issuer,
			clientId: c.env.oidc_client_id,
			clientSecret: c.env.oidc_client_secret || '',
			callbackUrl: c.env.oidc_callback_url,
			tokenEndpoint: String(c.env.oidc_token_url || `${issuer}/oauth2/token`).trim(),
			userinfoEndpoint: String(c.env.oidc_userinfo_url || `${issuer}/oauth2/userinfo`).trim()
		};
	},

	async exchangeOidcCode(c, oidcConfig, code, codeVerifier) {
		const reqParams = new URLSearchParams();
		reqParams.append('client_id', oidcConfig.clientId);
		if (oidcConfig.clientSecret) {
			reqParams.append('client_secret', oidcConfig.clientSecret);
		}
		reqParams.append('code', code);
		reqParams.append('redirect_uri', oidcConfig.callbackUrl);
		reqParams.append('grant_type', 'authorization_code');
		if (codeVerifier) {
			reqParams.append('code_verifier', codeVerifier);
		}

		const tokenRes = await fetch(oidcConfig.tokenEndpoint, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: reqParams.toString()
		});

		if (!tokenRes.ok) {
			throw new BizError(await this.readErrorText(tokenRes));
		}

		const token = await tokenRes.json();
		if (!token.access_token) {
			throw new BizError('OIDC未返回access_token');
		}
		return token;
	},

	async getOidcUserInfo(c, oidcConfig, accessToken, idTokenClaims) {
		const userRes = await fetch(oidcConfig.userinfoEndpoint, {
			headers: { Authorization: 'Bearer ' + accessToken }
		});

		if (!userRes.ok) {
			throw new BizError(await this.readErrorText(userRes));
		}

		return { ...idTokenClaims, ...await userRes.json() };
	},

	async resolveOidcRole(c, userInfo, idTokenClaims) {
		const roleName = this.firstOidcRoleName(userInfo.roles ?? idTokenClaims.roles);
		let roleRow = roleName ? await roleService.selectByOidcRole(c, roleName) : null;
		if (!roleRow) {
			roleRow = await roleService.selectDefaultRole(c);
		}
		if (!roleRow) {
			throw new BizError('默认权限身份不存在');
		}
		return roleRow;
	},

	firstOidcRoleName(roles) {
		if (!roles) {
			return '';
		}
		if (typeof roles === 'string') {
			return roles.split(',').map(item => item.trim()).filter(Boolean)[0] || '';
		}
		if (!Array.isArray(roles) || roles.length === 0) {
			return '';
		}
		const firstRole = roles[0];
		if (typeof firstRole === 'string') {
			return firstRole.trim();
		}
		if (!firstRole || typeof firstRole !== 'object') {
			return '';
		}
		return String(firstRole.role_name || firstRole.key || firstRole.name || firstRole.display_name || '').trim();
	},

	buildOidcUserId(issuer, sub) {
		return `oidc:${issuer}:${sub}`;
	},

	decodeJwtPayload(token) {
		try {
			const payload = token.split('.')[1];
			if (!payload) {
				return {};
			}
			const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
			const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, '=');
			return JSON.parse(atob(padded));
		} catch (e) {
			return {};
		}
	},

	async readErrorText(response) {
		const text = await response.text();
		return text || response.statusText;
	},

	async saveUser(c, userInfo) {

		const userInfoRow = await this.getById(c, userInfo.oauthUserId);

		if (!userInfoRow) {
			return await orm(c).insert(oauth).values(userInfo).returning().get();
		} else {
			return await orm(c).update(oauth).set(userInfo).where(eq(oauth.oauthUserId, userInfo.oauthUserId)).returning().get();
		}

	},

	async getById(c, oauthUserId) {
		return await orm(c).select().from(oauth).where(eq(oauth.oauthUserId, oauthUserId)).get();
	},

	async deleteByUserId(c, userId) {
		await this.deleteByUserIds(c, [userId]);
	},

	async deleteByUserIds(c, userIds) {
		await orm(c).delete(oauth).where(inArray(oauth.userId, userIds)).run();
	},

	//定时任务凌晨清除未绑定邮箱的oauth用户
	async clearNoBindOathUser(c) {
		await orm(c).delete(oauth).where(eq(oauth.userId, 0)).run();
	},

}

export default  oauthService
