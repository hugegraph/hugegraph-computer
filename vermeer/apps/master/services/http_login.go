/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. The ASF
licenses this file to You under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
*/

package services

import (
	"net/http"
	"strings"
	"vermeer/apps/auth"
	"vermeer/apps/common"

	"github.com/gin-gonic/gin"
)

//const cookieTokenExpire = 1 * time.Minute

type LoginRequest struct {
	Token *string `json:"token"`
}

type LoginHandler struct {
	common.SenHandler
}

func (l *LoginHandler) POST(ctx *gin.Context) {
	req := LoginRequest{}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		isBad(true, ctx, func() string { return "invalid login request" })
		return
	}
	if req.Token == nil {
		isBad(true, ctx, func() string { return "admin credential is required" })
		return
	}
	doTokenLogin(ctx, &req)
}

func doTokenLogin(ctx *gin.Context, req *LoginRequest) {
	if session, okPassword := auth.ExchangeAdminPassword(*req.Token); okPassword {
		setTokenCookie(ctx, session, auth.AdminSessionMaxAge)
		ok(ctx, "login success")
		return
	}
	token := auth.ToTokenBase58(*req.Token)
	if !auth.ValidLoginToken(token) {
		ctx.JSON(http.StatusUnauthorized, common.BaseResp{ErrCode: 1, Message: "invalid admin credential"})
		return
	}
	setTokenCookie(ctx, *req.Token, 0)
	ok(ctx, "login success")
}

func setTokenCookie(ctx *gin.Context, token string, maxAge int) {
	secure := ctx.Request.TLS != nil || strings.EqualFold(ctx.GetHeader("X-Forwarded-Proto"), "https")
	ctx.SetCookie(auth.CookieKey, token, maxAge, "/", "", secure, true)
}
