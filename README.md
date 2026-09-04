# 新一代 AI Agent 运行时框架

**Next-Gen AI Agent Runtime with Dynamic Trust Scheduling & Adaptive Isolation**

一个融合**语义网关、动态隔离决策、Token感知调度、凭证管理**的AI Agent运行时系统雏形。

## 🎯 核心架构

```
用户请求
   ↓
┌─────────────────────────────────────────────────────────────┐
│  [1] 语义网关 (Semantic Gateway)                            │
│     - 意图识别 (Intent Recognition)                        │
│     - 风险评分 (Risk Assessment)                           │
└─────────────────────┬───────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  [2] 动态隔离决策器 (Isolation Selector)                    │
│     - eBPF 轻量隔离 (risk < 0.4)                           │
│     - 容器隔离 (0.4 ≤ risk < 0.7)                         │
│     - VM/TEE 严格隔离 (risk ≥ 0.7)                        │
└─────────────────────┬───────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  [3] Token感知调度器 (Scheduler)                            │
│     - 节点选择 (Node Selection)                            │
│     - 资源分配 (Resource Allocation)                       │
└─────────────────────┬───────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  [4] 凭证注入与隔离执行 (Sandbox Engine)                    │
│     - 临时凭证生成 (Temporary Credentials)                 │
│     - 隔离环境创建 (Isolation Environment)                 │
│     - Task执行 (Task Execution)                           │
└─────────────────────┬───────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  [5] 状态与审计 (State & Audit)                             │
│     - 状态转移追踪 (State Transfer)                        │
│     - 审计日志 (Audit Logs)                               │
│     - 凭证清理 (Credential Cleanup)                       │
└─────────────────────┬───────────────────────────────────────┘
                      ↓
                   返回结果
```

## 📦 核心模块

### 1. **语义网关** (`semantic_gateway.py`)
- 解析 Agent 请求意图
- 通过关键词+规则评估风险分数 (0.0-1.0)
- 支持自定义风险评分模型

### 2. **动态隔离决策** (`isolation_selector.py`) ⭐
- **三层隔离机制**：
  - `eBPF_LSM`: 轻量级隔离，仅网络/系统调用限制
  - `CONTAINER`: 容器隔离，资源限制 + 文件系统沙箱
  - `VM_TEE`: VM/TEE隔离，完全硬件级隔离
- 根据风险分数自动选择隔离等级
- 支持手动覆盖隔离级别

### 3. **调度器** (`scheduler.py`)
- Token 成本估算
- 节点选择（支持多节点池）
- 资源约束检查
- SLA 优先级处理

### 4. **沙箱执行引擎** (`sandbox_engine.py`) ⭐
- 支持三种隔离方式执行：
  - eBPF 隔离: 直接进程执行 + eBPF 规则
  - 容器隔离: Docker 容器运行
  - VM 隔离: 虚拟机环境运行
- 凭证注入与权限控制
- 资源限制与超时管理
- 执行结果收集

### 5. **凭证管理** (`credential_manager.py`)
- 临时凭证生成（Token + Scope）
- TTL 机制（默认 30 秒）
- 权限验证与审计
- 自动清理过期凭证

### 6. **状态管理** (`state_manager.py`)
- 简化版内容寻址存储（CAS）
- 状态快照与恢复
- 审计日志记录

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 最小化示例

```python
from src.runtime import AgentRuntime

# 初始化运行时
runtime = AgentRuntime()

# 执行 Agent 任务
result = runtime.execute(
    tenant_id="tenant-001",
    agent_id="agent-001",
    task_intent="query database for user records",
    sensitivity_level="HIGH"
)

print(result)
# 输出: {
#   "status": "success",
#   "isolation_mode": "CONTAINER",
#   "risk_score": 0.65,
#   "output": "...",
#   "execution_time": 1.23
# }
```

### 完整示例（带风险评估与隔离选择）

```bash
python examples/basic_example.py
```

## 🔬 测试

运行完整测试套件：

```bash
pytest tests/ -v
```

或运行特定模块测试：

```bash
pytest tests/test_isolation_selector.py -v
pytest tests/test_sandbox_engine.py -v
```

## 📊 架构特点

| 特性 | 实现 |
|-----|------|
| **意图识别** | 关键词匹配 + 规则引擎 |
| **风险评分** | 多维度评估（0.0-1.0） |
| **动态隔离** | 三层：eBPF → 容器 → VM |
| **隔离执行** | 本地进程 / Docker / 虚拟机 |
| **凭证管理** | TTL + 权限作用域 |
| **审计追踪** | 完整的执行日志 |
| **可扩展性** | 模块化设计，易于扩展 |

## 🏗️ 项目结构

```
next-gen-agent-runtime/
├── README.md
├── requirements.txt
├── setup.py
├── src/
│   ├── __init__.py
│   ├── config.py                    # 全局配置
│   ├── semantic_gateway.py          # [模块1] 意图识别 + 风险评分
│   ├── isolation_selector.py        # [模块2] 三层隔离决策
│   ├── scheduler.py                 # [模块3] Token感知调度器
│   ├── sandbox_engine.py            # [模块4] 隔离执行引擎
│   ├── credential_manager.py        # [模块5] 凭证管理
│   ├── state_manager.py             # [模块6] 状态管理
│   ├── audit_logger.py              # 审计日志
│   ├── models.py                    # 数据模型
│   └── runtime.py                   # 主入口 + 协调
├── tests/
│   ├── __init__.py
│   ├── test_semantic_gateway.py
│   ├── test_isolation_selector.py
│   ├── test_scheduler.py
│   ├── test_sandbox_engine.py
│   ├── test_credential_manager.py
│   └── test_runtime.py
├── examples/
│   ├── basic_example.py             # 最小化示例
│   ├── risk_assessment_example.py   # 风险评估示例
│   ├── isolation_demo.py            # 隔离机制演示
│   ├── multi_agent_example.py       # 多Agent示例
│   └── config.yaml                  # 配置示例
├── docker/
│   ├── Dockerfile                   # 容器隔离环境
│   └── docker-compose.yml           # 本地开发环境
└── docs/
    ├── architecture.md              # 详细架构文档
    ├── isolation_mechanisms.md      # 隔离机制详解
    └── api_reference.md             # API 参考
```

## 📖 详细文档

- [架构设计](docs/architecture.md)
- [隔离机制详解](docs/isolation_mechanisms.md)
- [API 参考](docs/api_reference.md)

## 🔮 后续增强计划

- [ ] 真实 eBPF 规则集成（使用 Cilium 或 Falco）
- [ ] Kubernetes 容器编排支持
- [ ] 分布式状态管理（Redis/IPFS）
- [ ] 多区域节点池与数据驻留合规
- [ ] Web UI 管理界面
- [ ] Prometheus 监控指标
- [ ] 性能基准测试

## 📝 许可证

Apache License 2.0

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**开发者**: zhangxia-001  
**最后更新**: 2026-09-04
