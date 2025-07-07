/****************************************************************************
 * frameworks/ai/src/voice/ai_voice_plugin.h
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#include <stdlib.h>

#include "ai_common.h"
#include "ai_voice_plugin.h"

void* voice_plugin_init(voice_plugin_t* plugin, const voice_init_params_t* param)
{
    int ret;
    void* priv_ctx;

    priv_ctx = zalloc(plugin->priv_size);
    if (!priv_ctx) {
        return NULL;
    }

    if (plugin->init) {
        ret = plugin->init(priv_ctx, param);
        if (ret < 0) {
            AI_ERR("AI plugin:%s init failed: %d", plugin->name, ret);
            // free(priv_ctx);
            // priv_ctx = NULL;
            return NULL;
        }
    }

    return priv_ctx;
}

void voice_plugin_uinit(voice_plugin_t* plugin, void* engine, int sync)
{
    if (plugin->uninit && engine) {
        AI_INFO("AI plugin:%s uninit", plugin->name);
        plugin->uninit(engine);
    }

    if (sync) {
        free(engine);
        engine = NULL;
    }
}
