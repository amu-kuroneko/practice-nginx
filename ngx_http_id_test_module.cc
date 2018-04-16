extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <arpa/inet.h>
}

#include <random>
#include <string>

using std::string;

namespace {
  // プロトタイプ宣言
  u_char *StringToUChar(const string &value);
  string NgxStrToString(const ngx_str_t &value);
  string UCharToString(const u_char *start, const u_char *end);
  ngx_str_t StringToNgxStr(const string &value);

  char *NgxHttpIdTest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
  ngx_int_t NgxHttpIdTestHandler(ngx_http_request_t *r);
  ngx_int_t NgxHttpIdTestInit(ngx_conf_t *cf);

  const string ExtractPeerIp(ngx_http_request_t *r);
  const string ExtractIpV4(const struct sockaddr_in *addr);
  const string ExtractIpV6(const struct sockaddr_in6 *addr);
  const string ExtractMethod(ngx_http_request_t *r);
  const string ExtractUri(ngx_http_request_t *r);
  const string ExtractBody(ngx_http_request_t *r);
  const string ExtractHeaders(ngx_http_request_t *r);
  const string FindHeaderValue(ngx_http_request_t *r, const string &key);
  const string ConnectChain(ngx_chain_t *chain);
  ngx_table_elt_t *FindHeader(ngx_http_request_t *r, const string &key);

  void WriteHeader(ngx_http_request_t *r,
      const string &key, const string &value);

  // 固定で設定が必要そうな項目

  // コマンド群
  // 主にディレクティブの設定という認識
  ngx_command_t ngx_http_id_test_commands[] = {
    {
      ngx_string("id_test"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      NgxHttpIdTest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL
    },
    ngx_null_command // 最後のコマンドを示す
  };

  // モジュールコンテキストの設定
  // 各設定の準備をするための関数ポインタ郡という認識
  ngx_http_module_t ngx_http_id_test_module_ctx = {
    NULL, /* preconfiguration */
    &NgxHttpIdTestInit, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
  };

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

  // 実際の処理郡
  // このモジュールのセットアップ
  char *NgxHttpIdTest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    // location を利用
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

  ngx_int_t NgxHttpIdTestHandler(ngx_http_request_t *r) {
    std::random_device random;
    std::mt19937 mersenne_twister(random());
    if (mersenne_twister() % 2) {
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

    // レスポンスデータの設定
    string data = "test response data\n";
    // IP を取得
    data += ExtractPeerIp(r) + "\n";
    // メソッド名を取得
    const string method = ExtractMethod(r);
    data += method + "\n";
    // URI の取得
    if (r->args_start) {
      // GET 値有り
      data += UCharToString(r->uri_start, r->args_start - 1) + "\n";
      data += UCharToString(r->args_start, r->uri_end) + "\n";
    } else {
      // GET 値無し
      data += UCharToString(r->uri_start, r->uri_end) + "\n";
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

  const string ExtractMethod(ngx_http_request_t *r) {
    return NgxStrToString(r->method_name);
  }

  const string ExtractBody(ngx_http_request_t *r) {
    const char *data = reinterpret_cast<const char *>(r->request_start);
    const int len = r->request_end - r->request_start;
    return string(data, len);
    /*
    const ngx_http_request_body_t *body = r->request_body;
    if (!body) {
      return "no body";
    }
    return ConnectChain(body->bufs);
    */
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
    int length = key.length();
    u_char *lowcase_key = reinterpret_cast<u_char *>(ngx_palloc(r->pool, length));
    if (lowcase_key == NULL) {
      return NULL;
    }

    ngx_uint_t hash = 0;
    for (int i = 0; i < length; ++i) {
      lowcase_key[i] = ngx_tolower(key[i]);
      hash = ngx_hash(hash, lowcase_key[i]);
    }

    ngx_http_core_main_conf_t *cmcf
        = reinterpret_cast<ngx_http_core_main_conf_t *>(
            ngx_http_get_module_main_conf(r, ngx_http_core_module));

    ngx_http_header_t *header
        = reinterpret_cast<ngx_http_header_t *>(
            ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, length));

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
      header = reinterpret_cast<ngx_table_elt_t *>(
          ngx_list_push(&r->headers_out.headers));
      if (header == NULL) {
        return;
      }
      header->key = StringToNgxStr(key);
    }
    header->value = StringToNgxStr(value);
    header->hash = 1;
    return;
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
}

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

