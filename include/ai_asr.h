/****************************************************************************
 * frameworks/ai/include/ai_asr.h
 *
 * Copyright (C) 2020 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FRAMEWORKS_AI_INCLUDE_AI_ASR_H
#define FRAMEWORKS_AI_INCLUDE_AI_ASR_H

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * Included Files
 ****************************************************************************/

// #include "miwear_media_session.h"

/****************************************************************************
 * Public Types
 ****************************************************************************/

typedef struct asr_context asr_context_t;

typedef enum {
    asr_engine_type_volc,
    asr_engine_type_xiaoai
} asr_engine_type;

typedef struct asr_init_params {
    int version;
    uv_loop_t* loop;
    const char* locate; // CN
    const char* rec_mode; // short long
    const char* language; // zh-CN
    int slience_timeout; // 2000ms
    const char* app_id;
    const char* app_key;
    asr_engine_type engine_type;
} asr_init_params_t;

typedef enum {
    asr_event_unkonwn,
    asr_event_start,
    asr_event_cancel,
    asr_event_result,
    asr_event_complete,
    asr_event_error,
} asr_event_t;

typedef enum {
    asr_error_failed,
    asr_error_is_busy,
    asr_error_destroyed,
} asr_error_t;

typedef struct asr_result {
    char* result;
    int duration;
    asr_error_t error_code;
} asr_result_t;

typedef struct asr_audio_info {
    int version;
    char* format;
} asr_audio_info_t;

typedef void (*asr_callback_t)(asr_event_t event, const asr_result_t* result, void* cookie);

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/**
 * @brief Create ai asr engine.
 * @param[in] param asr init params
 * @return asr engine
 */
asr_context_t* ai_asr_create_engine(const asr_init_params_t* param);

/**
 * @brief Set asr engine listener.
 * @param[in] engine asr engine
 * @param[in] callback asr event callback
 * @param[in] cookie callback cookie
 * @return 0 on success, otherwise failed
 */
int ai_asr_set_listener(asr_context_t* engine, asr_callback_t callback, void* cookie);

/**
 * @brief Start asr engine.
 * @param[in] engine asr engine
 * @param[in] audio_info asr audio info
 * @return 0 on success, otherwise failed
 */
int ai_asr_start(asr_context_t* engine, const asr_audio_info_t* audio_info);

/**
 * @brief Finish asr engine.
 * @param[in] engine asr engine
 * @return 0 on success, otherwise failed
 */
int ai_asr_finish(asr_context_t* engine);

/**
 * @brief Cancel asr engine.
 * @param[in] engine asr engine
 * @return 0 on success, otherwise failed
 */
int ai_asr_cancel(asr_context_t* engine);

/**
 * @brief Destroy asr engine.
 * @param[in] engine asr engine
 * @return 0 on success, otherwise failed
 */
int ai_asr_is_busy(asr_context_t* engine);

/**
 * @brief Destroy asr engine.
 * @param[in] engine asr engine
 * @return 0 on success, otherwise failed
 */
int ai_asr_close(asr_context_t* engine);

#ifdef __cplusplus
}
#endif

#endif /* FRAMEWORKS_AI_INCLUDE_AI_ASR_H */
