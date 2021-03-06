function buildQuery(params) {
    return Object.keys(params).map(function(key) { return key + '=' + encodeURIComponent(params[key]) }).join('&')
}

function buildUrl(baseUrl, queries) {
    return baseUrl + '?' + buildQuery(queries)
}

function getQueryParameter(key) {
    queryParams = new URLSearchParams(location.search)
    return queryParams.get(key)
}

function naverLogin() {
    next = getQueryParameter('next')
    params = {
        response_type: 'code',
        client_id: 'PyX_R5l9wMp0PK3DoN_q',
        redirect_uri: 'http://chungsol.pythonanywhere.com/auth/login/naver/callback/' + (next ? '?next=' + next : ''),
        // redirect_uri: 'http://localhost:8000/auth/login/naver/callback/' + (next ? '?next=' + next : ''),
        state: document.querySelector('[name=csrfmiddlewaretoken]').value
    }

    const search = new URLSearchParams(location.search)
    console.log(search.get('reprompt'))
    if (search.get('reprompt') == 'true') {
        params.auth_type = 'reprompt'
    }
    url = buildUrl('https://nid.naver.com/oauth2.0/authorize', params)
    location.replace(url)
}