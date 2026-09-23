# Go 最终正确性审计（二）

结论：对基线 `92d4c0cb5495d57801d52893a8f0e8496a1c9182` → 最终产品 `4d15fa32764e26df58b16930d0e2503a90880002` 的七个产品 Go 文件差异，**未发现本轮优化新增的可确认正确性回归**。另外确认一项**基线已有、最终仍存在的失效后在途 RPC 回填窗口**，下文给出可达顺序及最小确定性复现提案，供 root 独立安排修复。未修改源码，没有运行 Go 编译、测试、基准、服务或任何远端操作。

审阅工作树 `/Users/edgeware/Local/Go-Reauth-Proxy` 干净；HEAD `bc0d28bc347347de4cda6dca22990ebd90130c88` 相比最终产品仅增加文档，`git diff 4d15fa3 HEAD -- pkg` 为空。独立子审阅亦核对了不可变 cache ownership、失效及 singleflight。

## 确认的既有问题：失效后在途旧 RPC 可以重新发布缓存

启用认证缓存 TTL 时，身份失效和全量 clear 只删除当时可见的 entry/index，没有使已启动的 RPC 或 singleflight 代次失效：`pkg/proxy/auth_cache.go:579–624`。RPC 随后返回时，普通 verify 在 `pkg/proxy/http_auth.go:575–606`、combined 在 `pkg/proxy/http_auth_combined.go:53–92` 无失效代次检查地写入；独立 preflight 同样在 `pkg/proxy/handler.go:1584–1605` 无条件发布符合 scope 的结果。

可达事件顺序：

1. 请求 A 用有效 session 发起 RPC，鉴权服务已经形成允许结果，但返回被延迟。
2. 请求 B 完成该 session 的 logout/revocation，Go 从认证代理响应的 Set-Cookie 执行失效（`handler.go:6046` → `authCacheInvalidateForSetCookieMutation` → `authCacheInvalidateByIdentityKeys`）。
3. A 的旧结果随后到达并缓存，过期时间从此次回填时开始计算。
4. 后续携带同一旧身份、相同 key 的请求可在该 TTL 内重新命中允许结果，而不是重验已撤销凭据。

这不同于“已取得旧 entry 的在途请求允许完成”：这里是失效结束后**重新向后续请求发布**旧结果。失效发生时缓存尚无该 key，也不会记录阻止回填的状态。`singleflight.Group` 同样未切换 generation，因此在旧 flight 完成前的新同 key 请求还可能加入旧 flight。

版本归因：baseline 的 `auth_cache.go:564–609` 与 `http_auth.go:764–817` 已有相同操作顺序；不是指针条目、二进制 key 或 lazy proto 引入。TTL=0 时没有该缓存发布路径；缓存命中已有的 TTL 窗口也不是这里新发现的失效竞态。

最小复现提案（本次未执行）：以 testAuthBridge 和两个 channel 控制调用，不起监听服务。设置 AuthCacheTTL>0；fake VerifyAuth 形成 authenticated allow + EXACT_REQUEST 后通知 started，并等待 release；主测试等待 started，调用同 identity 的失效（另测 clearAuthCache），释放 RPC，等待 executeAuthCheck 完成；断言 cache miss 将在当前版本失败。再用同 request 调 executeAuthCheck，检查 fake RPC 计数未增加，可证明影响后续请求。combined/preflight 用对应 response scopes 重复确定性场景，并在失效后、release 前加入第二个请求检查它是否错误共享旧 flight。基线与 final 都应先保存失败证据。

若决定修复，发布校验与失效需共用同一同步域，并让失效之后的新调用不能加入旧 flight；只调用 group.Forget 或只阻止 store 分别都不完整。可以评估有界 generation/epoch 方案，但本报告不指定未验证实现，也未修改冻结产品。

## 优化差异的核对结果

### 不可变缓存发布、读者和生命周期

- `auth_cache.go:535–556` 按值接收并发布独立 entry，复制 Set-Cookie 切片及 `map[string]struct{}` 权限集合。地图值本身无嵌套引用，浅 map clone 足够。`preflightCacheStore:559` 的 decision 仅含值字段/字符串，无需深复制。
- `authCacheGet:489`、`preflightCacheGet:512` 在 RLock 下取指针，再读不可变字段。过期删除重新持锁检查当前 entry 的过期状态，避免删除后来替换的未过期 entry。替换、身份失效、FIFO 淘汰、clear 均移除容器引用，不写旧 entry、不回收复用对象。
- 逐个查找生产消费者，未找到对已发布 map/slice/entry 的写入。`http_auth.go:655–677` 和 `auth_cache.go:968` 以值副本应用响应；权限 map 只读。普通 miss 返回自己的局部 entry，combined miss 返回 store 的克隆 entry，两者均无后续修改。
- 现有 `TestAuthCachePublishedEntrySurvivesReplacementAndInvalidation`（auth_cache_test.go:32）覆盖源 slice/map 修改不串入发布对象、并发替换/失效不改变已持有对象。它不覆盖上述在途 RPC 回填；不能把此测试解释为失效的线性化保证。

### Binary keys 与 exact → host 顺序

- `http_auth.go:465–474` 先查 exact，只有 exact miss/expired 才查 host；exact denial 不会被 host allow 覆盖。测试 `auth_cache_test.go:68` 显式断言 exact denial 优先及 expired exact 回落 host。
- 本次极小本地检查仅执行 Python 源文本比较：三种 key 函数除返回类型和 `sha256HexBytes(buf)` → `sha256.Sum256(buf)` 外完全相同；身份提取/augmentation、维度构造、字段分隔、RequestURI 构造及两种 TTL 函数与 baseline 文本一致。
- 因此 identity/access-token/user-agent、client IP、access mode、scheme、effective host、route identity/policy version 保留；exact verify 的 method/URI 和 preflight 的 matched/URI 保留，host scope 继续依原约定省略 method/URI。用于 logout/active tracking 的 identity 仍为十六进制字符串。
- `authCacheKey.flightKey`（auth_cache.go:38）保留完整 32 字节值；combined key（http_auth_combined.go:224）是固定前缀+32字节+分隔+32字节，不会因摘要内部含分隔符产生拼接歧义，也与普通 32 字节 flight key 分离。

### 完整 hit 快路径与 optional protobuf

- `http_auth_combined.go:96–126` 只将原 resolveCached 分支展开到无 closure 的 hit 路径：preflight stop 仍优先，单独 preflight hit 仍补 verify，单独 auth hit 仍补 preflight；required-preflight 与 cooldown 条件未改变。miss 函数仍二次检查 cache，再做 RPC。TTL0 仍不进入 singleflight/cache 快路。
- `handler.go:1184–1207` 继续用 targetSet/hostSet/routeIDSet 独立决定 protobuf 指针 presence；空字符串可 present，未解析 host 可 absent，不能由 getter 的空值合并这两种状态。nil request 的构造分支亦保留。
- `handler.go:1209–1245` 的 request/forwarded 字段、两个专用 access token、URI、Upgrade-only extra headers 与原构造一致。legacy fallback 的 headersToProto 继续复制 values（1270–1278）；没有将 combined 全量 header map 恢复或丢弃 Upgrade。
- 现有测试包括 invalid-target optional host absent（advanced_auth_test.go:349）、present-empty 与并发 materialization（combined_auth_test.go:45）、专用 token（322/362）、combined capability fallback（137）、host scope（391）、Set-Cookie/NONE 不缓存（436）。这是已存在测试覆盖的核对，不是本次重新运行。

### Lazy request context lifetime

- `newRequestAuthContext:1173` 保存本请求指针、值型 backend、IP/access mode/routeIdentity，首次 proto 在 `sync.Once` 内构造（1255–1267）。当前所有生产创建点均在路由/策略 context 准备后；下游 URL/header rewrite 位于鉴权完成后的 ReverseProxy `pr.Out`，没有找到创建后、首次 materialization 前修改上述认证输入的实际生产调用。
- singleflight closure 持有 requestAuth/sharedRequest，取消方可以先返回，但共享调用保留对象引用，直至其 bounded RPC 完成；此处无对象池、显式复用或跨请求 context 存储。`context.WithoutCancel` 和调用方 select cancellation 是基线已有行为；最终未更换 RPC timeout。
- `TestCombinedAuthCacheHitDoesNotMaterializeProto`（combined_auth_test.go:21）检查完整 hit 不生成 proto；并发 materialization 测试检查同一对象/presence；取消测试（505）检查调用方无需等待共享 RPC。当前对象及其返回 protobuf 仍是内部只读使用约定，不能把 sync.Once 解释为允许任意外部修改 request/protobuf，或证明所有可能的混合 legacy/combined 并发调用。

## 本次验证边界

没有重跑已经完成的 Cookie17、Trailer24、WebSocket/stream/error 或完整 race 套件。读取 `docs/experiments/auth-final-20260923/validation/commands.json`、all-tests.log、proxy-race.log：既有最终 4d15fa3 的 `go test ./...`、`go test -race ./pkg/proxy`、`go vet ./...` 均记录 exit0，race日志为 `ok ... 15.071s`。这些历史通过与本次静态审阅都不涵盖所有调度；特别不能宣称已排除上述失效回填问题。

现有六对本地收益仍属于相同 frozen 4d15fa3 的 lean fixture，不能为未来竞态修复沿用“无额外开销”结论。若 root 修复并改变产品 SHA，应保存该独立修复的确定性测试和必要的局部性能复核；本次未新增任何性能结果。
