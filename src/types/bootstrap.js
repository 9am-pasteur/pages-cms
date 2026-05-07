/**
 * @typedef {'github' | 'gitlab' | 'proxy_github_app'} ModeId
 */

/**
 * @typedef {Object} DirectModeDescriptor
 * @property {'github' | 'gitlab'} id
 * @property {'direct'} type
 * @property {string} label
 * @property {boolean} enabled
 */

/**
 * @typedef {Object} ProxyModeDescriptor
 * @property {'proxy_github_app'} id
 * @property {'proxy'} type
 * @property {string} label
 * @property {boolean} enabled
 * @property {{
 *   provider: 'github_app',
 *   version: 'v1',
 *   basePath: string
 * }} proxy
 */

/**
 * @typedef {Object} BootstrapResponse
 * @property {{
 *   accessEnabled: boolean,
 *   email?: string,
 *   isAdmin: boolean,
 *   roles: string[]
 * }} auth
 * @property {(DirectModeDescriptor | ProxyModeDescriptor)[]} modes
 * @property {ModeId[]} allowedModes
 * @property {ModeId | null} defaultMode
 */

export {};
