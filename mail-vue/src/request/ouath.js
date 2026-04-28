import http from '@/axios/index.js';

export function oauthLinuxDoLogin(code) {
    return http.post('/oauth/linuxDo/login',{code})
}

export function oauthOidcLogin(code, codeVerifier) {
    return http.post('/oauth/oidc/login', {code, codeVerifier})
}

export function oauthBindUser(form) {
    return http.put('/oauth/bindUser', form)
}
