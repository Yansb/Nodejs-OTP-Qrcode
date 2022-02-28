const authService = require('../services/auth')

const authenticate = async ctx => {
  const { email, password, twoFactorToken } = ctx.request.body
  const { accessToken, refreshToken, refreshTokenExpiration, twoFactorEnabled } = await authService.authenticate({ email, password, twoFactorToken })
  if (!accessToken && twoFactorEnabled) {
    ctx.body = { twoFactorEnabled }
  } else {
    ctx.cookies.set('refreshToken', refreshToken, { httpOnly: true, expires: refreshTokenExpiration })
    ctx.body = {
      accessToken,
    }
  }
}

const refreshToken = async ctx => {
  const { accessToken, refreshToken, refreshTokenExpiration } = await authService.refreshToken({ token: ctx.cookies.get('refreshToken') })
  ctx.cookies.set('refreshToken', refreshToken, { httpOnly: true, expires: refreshTokenExpiration })
  ctx.body = {
    accessToken,
  }
}

const logout = async ctx => {
  const { allDevices } = ctx.request.body
  await authService.logout({ token: ctx.cookies.get('refreshToken'), allDevices })
  ctx.cookies.set('refreshToken', '')
  ctx.body = {}
}

const generateQrCode = async ctx => {
  const qrcode = await authService.generateQrCode(ctx.state.userId)
  ctx.body = `<img src=${qrcode}>`
}
const activateTwoFactor = async ctx => {
  const { token } = ctx.request.body
  return authService.activateTwoFactor({ userId: ctx.state.userId, token }).then(ctx.body = { activated: true })
}

module.exports = {
  authenticate,
  refreshToken,
  logout,
  generateQrCode,
  activateTwoFactor,
}
