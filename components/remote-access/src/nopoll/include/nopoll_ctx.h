/*
 *  LibNoPoll: A websocket library
 *  Copyright (C) 2017 Advanced Software Production Line, S.L.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 *  
 *  You may find a copy of the license under this software is released
 *  at COPYING file. This is LGPL software: you are welcome to develop
 *  proprietary applications using this library without any royalty or
 *  fee but returning back any change, improvement or addition in the
 *  form of source code, project image, documentation patches, etc.
 *
 *  For commercial support on build Websocket enabled solutions
 *  contact us:
 *          
 *      Postal address:
 *         Advanced Software Production Line, S.L.
 *         Av. Juan Carlos I, Nº13, 2ºC
 *         Alcalá de Henares 28806 Madrid
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/nopoll
 */
#ifndef __NOPOLL_CTX_H__
#define __NOPOLL_CTX_H__

#include <nopoll.h>

BEGIN_C_DECLS

noPollCtx    * nopoll_ctx_new (void);

nopoll_bool    nopoll_ctx_ref (noPollCtx * ctx);

void           nopoll_ctx_unref (noPollCtx * ctx);

void           nopoll_ctx_set_protocol_version (noPollCtx * ctx, int version);

void           nopoll_ctx_free (noPollCtx * ctx);

void           nopoll_ctx_set_read_write_handle(noPollCtx *ctx, noPollRead read_handle, noPollRead write_handle);
void           nopoll_ctx_set_userdata(noPollCtx *ctx, void *userdata);
END_C_DECLS

#endif
