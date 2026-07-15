export const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:5000/api')
    .replace(/\/$/, '');

let refreshPromise = null;

const CSRF_COOKIE = import.meta.env.VITE_CSRF_COOKIE_NAME || 'vdcms_csrf';
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const getCookie = (name) => {
    if (typeof document === 'undefined') return '';
    return document.cookie
        .split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith(`${name}=`))
        ?.slice(name.length + 1) || '';
};

const parseResponse = async (response) => {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        const data = await response.json();
        return { ...data, status: response.status };
    }

    return {
        success: false,
        status: response.status,
        message: response.status === 404
            ? 'Không tìm thấy API trên backend. Hãy khởi động lại backend bằng mã nguồn mới nhất.'
            : `Máy chủ trả về phản hồi không hợp lệ (HTTP ${response.status}).`,
    };
};

const requestRefresh = async () => {
    if (!refreshPromise) {
        const csrfToken = getCookie(CSRF_COOKIE);
        refreshPromise = fetch(`${BASE_URL}/auth/refresh`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...(csrfToken ? { 'X-CSRF-Token': decodeURIComponent(csrfToken) } : {}),
            },
        })
            .then(async (response) => ({ response, data: await parseResponse(response) }))
            .finally(() => {
                refreshPromise = null;
            });
    }
    return refreshPromise;
};

export const refreshAuthSession = async () => {
    try {
        const { response, data } = await requestRefresh();
        return response.ok && data.success ? data : null;
    } catch {
        return null;
    }
};

const makeRequest = async (endpoint, options = {}, allowRefresh = true) => {
    const isFormData = options.body instanceof FormData;
    const method = String(options.method || 'GET').toUpperCase();
    const csrfToken = UNSAFE_METHODS.has(method) ? getCookie(CSRF_COOKIE) : '';
    const headers = {
        ...(!isFormData && options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(csrfToken ? { 'X-CSRF-Token': decodeURIComponent(csrfToken) } : {}),
        ...options.headers,
    };
    const response = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
        credentials: 'include',
    });
    const data = await parseResponse(response);

    if (response.status === 401 && allowRefresh) {
        const refreshed = await refreshAuthSession();
        if (refreshed) return makeRequest(endpoint, options, false);
        window.dispatchEvent(new CustomEvent('auth:expired'));
    }

    return data;
};

export const apiClient = async (endpoint, options = {}) => {
    try {
        return await makeRequest(endpoint, options);
    } catch {
        return { success: false, status: 0, message: 'Không thể kết nối tới máy chủ.' };
    }
};

export const apiGet = (endpoint) => apiClient(endpoint, { method: 'GET' });
export const apiPost = (endpoint, body) => apiClient(endpoint, {
    method: 'POST',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
export const apiPut = (endpoint, body) => apiClient(endpoint, {
    method: 'PUT',
    body: JSON.stringify(body),
});
export const apiDelete = (endpoint) => apiClient(endpoint, { method: 'DELETE' });
export const apiPatch = (endpoint, body) => apiClient(endpoint, {
    method: 'PATCH',
    body: JSON.stringify(body),
});
export const apiUpload = (endpoint, formData) => apiClient(endpoint, {
    method: 'POST',
    body: formData,
});
