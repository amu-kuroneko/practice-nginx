extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <arpa/inet.h>
}

#include <random>
#include <string>
#include <memory>

using std::string;
using std::unique_ptr;

// プロトタイプ宣言
u_char *StringToUChar(const string &value);
string NgxStrToString(const ngx_str_t &value);
string UCharToString(const u_char *start, const u_char *end);
ngx_str_t StringToNgxStr(const string &value);
ngx_str_t StringToNgxStr(ngx_http_request_t *r, const string &value);
ngx_uint_t StringToLowerUChar(u_char *lowcase, const string &value);

char *NgxHttpIdTest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *NgxHttpIdTest2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t NgxHttpIdTestHandler(ngx_http_request_t *r);
ngx_int_t InitVariable(ngx_conf_t *cf);
ngx_int_t NgxHttpIdTestInit(ngx_conf_t *cf);
void *NgxHttpIdTestCreateMain(ngx_conf_t *cf);
char *NgxHttpIdTestInitMain(ngx_conf_t *cf, void *conf);
void *NgxHttpIdTestCreateServer(ngx_conf_t *cf);
char *NgxHttpIdTestInitServer(ngx_conf_t *cf, void *prev, void *conf);
void *NgxHttpIdTestCreateLocation(ngx_conf_t *cf);
char *NgxHttpIdTestInitLocation(ngx_conf_t *cf, void *prev, void *conf);
ngx_int_t GetVariableHandler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

const string ExtractPeerIp(ngx_http_request_t *r);
const string ExtractIpV4(const struct sockaddr_in *addr);
const string ExtractIpV6(const struct sockaddr_in6 *addr);
const string ExtractMethod(ngx_http_request_t *r);
const string ExtractUri(ngx_http_request_t *r);
const string ExtractQuery(ngx_http_request_t *r);
const string ExtractBody(ngx_http_request_t *r);
const string ExtractHeaders(ngx_http_request_t *r);
const string FindHeaderValue(ngx_http_request_t *r, const string &key);
const string ConnectChain(ngx_chain_t *chain);
bool SetVariable(ngx_http_request_t *r, const string &key, const string &value);
ngx_table_elt_t *FindHeader(ngx_http_request_t *r, const string &key);

void WriteHeader(ngx_http_request_t *r,
    const string &key, const string &value);

// config 用構造体
struct TestConfig {
  ngx_flag_t dummy;
  ngx_flag_t enable;
};

// 固定で設定が必要そうな項目

// コマンド群
// 主にディレクティブの設定という認識
ngx_command_t ngx_http_id_test_commands[] = {
  {
    ngx_string("id_test"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    NgxHttpIdTest,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(TestConfig, dummy),
    NULL
  },
  {
    ngx_string("id_test2"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    NgxHttpIdTest2,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(TestConfig, dummy),
    NULL
  },
  {
    ngx_string("enable_kuroneko"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(TestConfig, enable),
    NULL
  },
  ngx_null_command // 最後のコマンドを示す
};

// モジュールコンテキストの設定
// 各設定の準備をするための関数ポインタ郡という認識
ngx_http_module_t ngx_http_id_test_module_ctx = {
  InitVariable, /* preconfiguration */
  NgxHttpIdTestInit, /* postconfiguration */

  NgxHttpIdTestCreateMain, /* create main configuration */
  NgxHttpIdTestInitMain, /* init main configuration */

  NgxHttpIdTestCreateServer, /* create server configuration */
  NgxHttpIdTestInitServer, /* merge server configuration */

  NgxHttpIdTestCreateLocation, /* create location configuration */
  NgxHttpIdTestInitLocation /* merge location configuration */
};

// モジュールの設定
// この構造体を読み込むことで Nginx にモジュールとして機能させることができる認識
ngx_module_t ngx_http_id_test_module = {
  NGX_MODULE_V1,
  &ngx_http_id_test_module_ctx, /* module context */
  ngx_http_id_test_commands, /* module directives */
  NGX_HTTP_MODULE, /* module type */
  NULL, /* init master */
  NULL, /* init module */
  NULL, /* init process */
  NULL, /* init thread */
  NULL, /* exit thread */
  NULL, /* exit process */
  NULL, /* exit master */
  NGX_MODULE_V1_PADDING
};

// 初期化する変数
static ngx_http_variable_t ngx_http_variable
  = {ngx_string("test_variable"), NULL, NULL, 0, 0, NGX_HTTP_ACCESS_PHASE};

// 初期化をしておかないと，config で設定することができない
ngx_int_t InitVariable(ngx_conf_t *cf) {
  if (!cf) { // DEBUG
    NgxHttpIdTest(nullptr, nullptr, nullptr);
    NgxHttpIdTestCreateMain(nullptr);
    NgxHttpIdTestInitMain(nullptr, nullptr);
    NgxHttpIdTestCreateServer(nullptr);
    NgxHttpIdTestInitServer(nullptr, nullptr, nullptr);
    NgxHttpIdTestCreateLocation(nullptr);
    NgxHttpIdTestInitLocation(nullptr, nullptr, nullptr);
  }
  ngx_http_variable_t *variable
    = ngx_http_add_variable(cf, &ngx_http_variable.name, ngx_http_variable.flags);
  if (variable == NULL) {
    return NGX_ERROR;
  }
  variable->data = ngx_http_variable.data;
  // get_handler が設定されていないと設定した変数を利用することができない
  variable->get_handler = GetVariableHandler;
  return NGX_OK;
}

// このモジュールの初期設定を行う
ngx_int_t NgxHttpIdTestInit(ngx_conf_t *cf) {
  // ngx_http_core_module から main conf を取得する
  ngx_http_core_main_conf_t *cmcf;
  cmcf = reinterpret_cast<ngx_http_core_main_conf_t *>(
      ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module));

  // handler をセットする
  ngx_http_handler_pt *handler;
  handler = reinterpret_cast<ngx_http_handler_pt *>(
      ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers));
  if (handler == NULL) {
    return NGX_ERROR;
  }
  *handler = NgxHttpIdTestHandler;
  return NGX_OK;
}

// http コンテキストに関する config の初期化
void *NgxHttpIdTestCreateMain(ngx_conf_t *cf) {
  TestConfig *conf = static_cast<TestConfig *>(ngx_palloc(cf->pool, sizeof(TestConfig)));
  conf->dummy = NGX_CONF_UNSET;
  conf->enable = NGX_CONF_UNSET;
  printf("%s: %p\n", __func__, conf);
  return conf;
}
// http コンテキストに関する config の作成
char *NgxHttpIdTestInitMain(ngx_conf_t *cf, void *conf) {
  TestConfig *config = static_cast<TestConfig *>(conf);
  printf("%s: conf(%ld,%ld)\n", __func__, config->dummy, config->enable);
  return NGX_CONF_OK;
}
// server コンテキストに関する config の初期化
void *NgxHttpIdTestCreateServer(ngx_conf_t *cf) {
  TestConfig *conf = static_cast<TestConfig *>(ngx_palloc(cf->pool, sizeof(TestConfig)));
  conf->dummy = NGX_CONF_UNSET;
  conf->enable = NGX_CONF_UNSET;
  printf("%s: %p\n", __func__, conf);
  return conf;
}
// server コンテキストに関する config の作成
char *NgxHttpIdTestInitServer(ngx_conf_t *cf, void *prev, void *conf) {
  TestConfig *previous = static_cast<TestConfig *>(prev);
  TestConfig *config = static_cast<TestConfig *>(conf);
  printf("%s: prev(%ld,%ld) conf(%ld,%ld)\n", __func__, previous->dummy, previous->enable, config->dummy, config->enable);
  return NGX_CONF_OK;
}
// location コンテキストに関する config の初期化
void *NgxHttpIdTestCreateLocation(ngx_conf_t *cf) {
  TestConfig *conf = static_cast<TestConfig *>(ngx_palloc(cf->pool, sizeof(TestConfig)));
  conf->dummy = NGX_CONF_UNSET;
  conf->enable = NGX_CONF_UNSET;
  printf("%s: %p\n", __func__, conf);
  return conf;
}
// location コンテキストに関する config の作成
char *NgxHttpIdTestInitLocation(ngx_conf_t *cf, void *prev, void *conf) {
  TestConfig *previous = static_cast<TestConfig *>(prev);
  TestConfig *config = static_cast<TestConfig *>(conf);
  printf("%s: prev(%ld,%ld) conf(%ld,%ld)\n", __func__, previous->dummy, previous->enable, config->dummy, config->enable);
  return NGX_CONF_OK;
}

// SetVariable の内容を行うことで，ここで明示的な値の設定を行わなくても値を設定してくれる
// もし固定の値を入れたいのであれば，此処で固定値を設定することが可能になる
ngx_int_t GetVariableHandler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
  if (data == 0) {
    v->not_found = 1;
  }
  return NGX_OK;
}

// 実際の処理郡
// このモジュールのセットアップ
char *NgxHttpIdTest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  // location を利用
  if (cf) { // DEBUG
    printf("%s\n", __func__);
    return NGX_CONF_OK;
  }
  ngx_http_core_loc_conf_t *clcf;

  // locatin に追加するためのデータを取得
  clcf = static_cast<ngx_http_core_loc_conf_t *>(
      ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module));

  // dummy
  if (!clcf) {
      return reinterpret_cast<char *>(NGX_CONF_ERROR);
  }
  // ハンドラを設定
  // clcf->handler = NgxHttpIdTestHandler;
  return NGX_CONF_OK;
}

char *NgxHttpIdTest2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *args = static_cast<ngx_str_t *>(cf->args->elts);
  printf("%s: argc(%zu)", __func__, cf->args->nelts);
  for (ngx_uint_t i = 0; i < cf->args->nelts; ++i) {
    printf(", argv[%zu](%s)", i, args[i].data); 
  }
  putchar('\n');
  return NGX_CONF_OK;
}

ngx_int_t NgxHttpIdTestHandler(ngx_http_request_t *r) {
  /*
  // URI の取得
  if (r->args_start) {
    // GET 値有り
    data += UCharToString(r->uri_start, r->args_start - 1) + "\n";
    data += UCharToString(r->args_start, r->uri_end) + "\n";
  } else {
    // GET 値無し
    data += UCharToString(r->uri_start, r->uri_end) + "\n";
  }
  */

  TestConfig *config = static_cast<TestConfig *>(
      ngx_http_get_module_loc_conf(r, ngx_http_id_test_module));
  printf("%s: conf(%ld)\n", __func__, config->enable);

  // URI の取得
  const string uri = ExtractUri(r);
  // GET Query の取得
  const string query = ExtractQuery(r);

  // uri が / の場合のみ分岐
  if (uri == "/") {
    std::random_device random;
    std::mt19937 mersenne_twister(random());
    SetVariable(r, "test_variable", std::to_string(mersenne_twister()));
    WriteHeader(r, "test_header", std::to_string(mersenne_twister()));
    return NGX_DECLINED;
  }

  ngx_buf_t *buffer;
  ngx_chain_t out;

  // Content-Type を設定
  const string content_type = "text/plain";
  r->headers_out.content_type.len = content_type.length();
  r->headers_out.content_type.data = StringToUChar(content_type);

  // レスポンスデータの準備
  buffer = static_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));

  // バッファチェインの設定
  out.buf = buffer;
  out.next = NULL;

  // メソッド名を取得
  const string method = ExtractMethod(r);

  // レスポンスデータの設定
  string data = "test response data\n";
  // IP を取得
  data += ExtractPeerIp(r) + "\n";
  data += method + "\n";

  // URI
  data += uri + "\n";
  if (!query.empty()) {
    data += query + "\n";
  }

  // ホスト名の取得
  data += UCharToString(r->host_start, r->host_end) + "\n";
  // ヘッダの取得
  data += ExtractHeaders(r);
  // ヘッダからホスト名を取得
  data += FindHeaderValue(r, "Host") + "\n";
  // Body の取得
  data += ExtractBody(r) + "\n";

  buffer->pos = StringToUChar(data); // 文字列ポインタの開始位置
  buffer->last = buffer->pos + data.length(); // 文字列ポインタの終了位置
  buffer->memory = 1; // readonly
  buffer->last_buf = 1; // バッファの終了を示す

  // HTTP レスポンスコードの設定
  r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
  // 全体のコンテンツ長を設定
  r->headers_out.content_length_n = data.length();

  // ヘッダ情報を送信
  ngx_http_send_header(r);

  // body 情報を送信
  return ngx_http_output_filter(r, &out);
}

// IP の抽出
const string ExtractPeerIp(ngx_http_request_t *r) {
  struct sockaddr *addr = r->connection->sockaddr;
  switch (addr->sa_family) {
    case AF_INET: 
      return ExtractIpV4(
          reinterpret_cast<const struct sockaddr_in *>(addr));

    case AF_INET6:
      return ExtractIpV6(
          reinterpret_cast<const struct sockaddr_in6 *>(addr));

    default:
      return "UNKNOWN";
  }
}

const string ExtractIpV4(const struct sockaddr_in *addr) {
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
  return string(ip);
}

const string ExtractIpV6(const struct sockaddr_in6 *addr) {
  char ip[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &addr->sin6_addr, ip, INET6_ADDRSTRLEN);
  return string(ip);
}

const string ExtractUri(ngx_http_request_t *r) {
  return UCharToString(r->uri_start,
      r->args_start ? r->args_start - 1 : r->uri_end);
}

const string ExtractQuery(ngx_http_request_t *r) {
  return r->args_start
    ? UCharToString(r->args_start, r->uri_end) : "";
}

const string ExtractMethod(ngx_http_request_t *r) {
  return NgxStrToString(r->method_name);
}

const string ExtractBody(ngx_http_request_t *r) {
  const char *data = reinterpret_cast<const char *>(r->request_start);
  const int len = r->request_end - r->request_start;
  if (r == NULL) { // DEBUG 用
    const ngx_http_request_body_t *body = r->request_body;
    if (!body) {
      return "no body";
    }
    return ConnectChain(body->bufs);
  }

  return string(data, len);
}

const string ExtractHeaders(ngx_http_request_t *r) {
  string result;
  ngx_list_part_t *part = &r->headers_in.headers.part;
  for (; part; part = part->next) {
    ngx_table_elt_t *headers = reinterpret_cast<ngx_table_elt_t *>(part->elts);
    for (unsigned int i = 0; i < part->nelts; ++i) {
      result += NgxStrToString(headers[i].key) + ": "
        + NgxStrToString(headers[i].value) + "\n";
    }
  }
  return result;
}

const string FindHeaderValue(ngx_http_request_t *r, const string &key) {
  ngx_table_elt_t *header = FindHeader(r, key);
  if (header) {
    return NgxStrToString(header->value);
  } else {
    return "";
  }
}

const string ConnectChain(ngx_chain_t *chain) {
  string result;
  for (; chain; chain = chain->next) {
    const char *data = reinterpret_cast<const char *>(chain->buf->pos);
    const int len = chain->buf->last - chain->buf->pos;
    result += string(data, len);
  }
  return result;
}

ngx_table_elt_t *FindHeader(ngx_http_request_t * r, const string &key) {
  u_char *lowcase_key = reinterpret_cast<u_char *>(ngx_palloc(r->pool, key.length() + 1));
  if (lowcase_key == NULL) {
    return NULL;
  }

  ngx_uint_t hash = StringToLowerUChar(lowcase_key, key);

  ngx_http_core_main_conf_t *cmcf
      = reinterpret_cast<ngx_http_core_main_conf_t *>(
          ngx_http_get_module_main_conf(r, ngx_http_core_module));

  ngx_http_header_t *header
      = reinterpret_cast<ngx_http_header_t *>(
          ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, key.length()));

  if (header == NULL || header->offset == 0) {
    return NULL;
  }
  return *reinterpret_cast<ngx_table_elt_t **>(
      reinterpret_cast<char *>(&r->headers_in) + header->offset);
}

void WriteHeader(ngx_http_request_t *r,
    const string &key, const string &value) {
  ngx_table_elt_t *header = FindHeader(r, key);
  if (header == NULL) {
    // headers_out ではなく headers_in を書き換えることで proxy されるヘッダを変更することが可能になる
    header = reinterpret_cast<ngx_table_elt_t *>(
        ngx_list_push(&r->headers_in.headers));
    if (header == NULL) {
      return;
    }
    header->key = StringToNgxStr(r, key);
  }
  header->value = StringToNgxStr(r, value);
  header->hash = 1;
  return;
}

bool SetVariable(ngx_http_request_t *r,
    const string &key, const string &value) {
  u_char *lowcase_key = static_cast<u_char *>(
      ngx_palloc(r->pool, key.length() + 1));
  if (lowcase_key == NULL) {
    return false;
  }
  ngx_uint_t hash = StringToLowerUChar(lowcase_key, key);

  u_char *char_value = static_cast<u_char *>(
      ngx_palloc(r->pool, value.length() + 1));
  if (char_value == NULL) {
    return false;
  }

  ngx_memcpy(char_value, value.c_str(), value.length());
  char_value[value.length()] = '\0';

  const ngx_str_t name = StringToNgxStr(key);

  ngx_http_core_main_conf_t *cmcf
    = static_cast<ngx_http_core_main_conf_t *>(
        ngx_http_get_module_main_conf(r, ngx_http_core_module));
  ngx_http_variable_t *variable
    = static_cast<ngx_http_variable_t *>(
        ngx_hash_find(&cmcf->variables_hash, hash, name.data, name.len));

  if (!variable && !(variable->flags & NGX_HTTP_VAR_CHANGEABLE)
      && !(variable->flags & NGX_HTTP_VAR_INDEXED)) {
    return false;
  }

  ngx_http_variable_value_t *variable_value = &r->variables[variable->index];
  variable_value->valid = 1;
  variable_value->not_found = 0;
  variable_value->no_cacheable = 0;
  variable_value->data = char_value;
  variable_value->len = value.length();

  return true;
}

// ユーティリティ
u_char *StringToUChar(const string &value) {
  return reinterpret_cast<u_char *>(const_cast<char *>(value.c_str()));
}

string NgxStrToString(const ngx_str_t &value) {
  return string(reinterpret_cast<const char *>(value.data), value.len);
}

string UCharToString(const u_char *start, const u_char *end) {
  return string(reinterpret_cast<const char *>(start), end - start);
}

ngx_str_t StringToNgxStr(const string &value) {
  ngx_str_t new_value;
  new_value.data = StringToUChar(value);
  new_value.len = value.length();
  return new_value;
}

ngx_str_t StringToNgxStr(ngx_http_request_t *r, const string &value) {
  u_char *data = reinterpret_cast<u_char *>(ngx_palloc(r->pool, value.length()));
  ngx_memcpy(data, value.c_str(), value.length());
  ngx_str_t new_value;
  new_value.data = data;
  new_value.len = value.length();
  return new_value;
}


ngx_uint_t StringToLowerUChar(u_char *lowcase, const string &value){
  int length = value.length();
  ngx_uint_t hash = 0;
  for (int i = 0; i < length; ++i) {
    lowcase[i] = ngx_tolower(value[i]);
    hash = ngx_hash(hash, lowcase[i]);
  }
  lowcase[length] = '\0';
  return hash;
}

