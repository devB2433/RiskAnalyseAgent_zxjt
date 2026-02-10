"""
模型路由层使用示例
演示三种路由策略的使用
"""
import sys
import os
import asyncio

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.model_routing import (
    ModelRouter,
    ModelRegistry,
    TaskComplexity,
    ModelCapability
)


async def example_rule_based_routing():
    """示例1：基于规则的路由"""
    print("\n" + "="*60)
    print("示例1：基于规则的路由")
    print("="*60)

    router = ModelRouter(default_strategy="rule_based")

    # 1. 使用默认规则
    print("\n1.1 使用默认规则")
    tasks = [
        ("simple_qa", "简单问答"),
        ("code_generation", "代码生成"),
        ("complex_reasoning", "复杂推理"),
        ("translation", "翻译任务")
    ]

    for task_type, description in tasks:
        decision = await router.route(
            task_type=task_type,
            task_description=description
        )
        print(f"  {description}:")
        print(f"    → 选择模型: {decision.selected_model.name}")
        print(f"    → 原因: {decision.reason}")

    # 2. 添加自定义规则
    print("\n1.2 添加自定义规则")
    router.add_rule("security_analysis", "gpt-4o")
    router.add_rule("log_parsing", "glm-4-flash")

    decision = await router.route(
        task_type="security_analysis",
        task_description="分析安全日志"
    )
    print(f"  安全分析:")
    print(f"    → 选择模型: {decision.selected_model.name}")
    print(f"    → 原因: {decision.reason}")

    # 3. 按复杂度路由
    print("\n1.3 按复杂度路由")
    complexities = [
        (TaskComplexity.SIMPLE, "简单任务"),
        (TaskComplexity.MEDIUM, "中等任务"),
        (TaskComplexity.COMPLEX, "复杂任务"),
        (TaskComplexity.VERY_COMPLEX, "极复杂任务")
    ]

    for complexity, desc in complexities:
        decision = await router.route(
            task_type="general",
            complexity=complexity
        )
        print(f"  {desc}:")
        print(f"    → 选择模型: {decision.selected_model.name}")


async def example_intelligent_routing():
    """示例2：智能路由"""
    print("\n" + "="*60)
    print("示例2：智能路由（AI自动选择）")
    print("="*60)

    router = ModelRouter(default_strategy="intelligent")

    # 1. 简单任务
    print("\n2.1 简单任务")
    decision = await router.route(
        task_type="simple_task",
        task_description="将这段文本翻译成英文",
        complexity=TaskComplexity.SIMPLE,
        prefer_speed=True,
        strategy="intelligent"
    )
    print(f"  选择模型: {decision.selected_model.name}")
    print(f"  原因: {decision.reason}")
    print(f"  置信度: {decision.confidence}")

    # 2. 复杂任务
    print("\n2.2 复杂任务")
    decision = await router.route(
        task_type="complex_analysis",
        task_description="分析这段代码的安全漏洞，并提供修复建议",
        complexity=TaskComplexity.VERY_COMPLEX,
        required_capabilities=[
            ModelCapability.CODE_GENERATION,
            ModelCapability.REASONING
        ],
        strategy="intelligent"
    )
    print(f"  选择模型: {decision.selected_model.name}")
    print(f"  原因: {decision.reason}")
    print(f"  置信度: {decision.confidence}")

    # 3. 带成本限制
    print("\n2.3 带成本限制的任务")
    decision = await router.route(
        task_type="cost_sensitive",
        task_description="生成一份报告摘要",
        max_cost=0.01,  # 最多0.01美元/1k tokens
        min_quality=7.0,  # 最低质量7分
        strategy="intelligent"
    )
    print(f"  选择模型: {decision.selected_model.name}")
    print(f"  成本: ${decision.selected_model.cost_per_1k_tokens}/1k tokens")
    print(f"  质量: {decision.selected_model.quality_score}/10")


async def example_config_based_routing():
    """示例3：基于配置的路由"""
    print("\n" + "="*60)
    print("示例3：基于配置的路由")
    print("="*60)

    router = ModelRouter(default_strategy="config_based")

    # 1. 设置Agent模型配置
    print("\n3.1 配置不同Agent使用不同模型")
    router.set_agent_model("compromised_host_analyzer", "gpt-4o")
    router.set_agent_model("anomalous_login_analyzer", "claude-3-sonnet")
    router.set_agent_model("simple_classifier", "glm-4-flash")

    agents = [
        "compromised_host_analyzer",
        "anomalous_login_analyzer",
        "simple_classifier"
    ]

    for agent_name in agents:
        decision = await router.route(
            task_type="analysis",
            agent_name=agent_name,
            strategy="config_based"
        )
        print(f"  {agent_name}:")
        print(f"    → 使用模型: {decision.selected_model.name}")

    # 2. 保存和加载配置
    print("\n3.2 保存配置到文件")
    config_file = "agent_models.json"
    router.save_agent_config(config_file)
    print(f"  ✓ 配置已保存到: {config_file}")

    # 3. 从文件加载配置
    print("\n3.3 从文件加载配置")
    new_router = ModelRouter(default_strategy="config_based")
    new_router.load_agent_config(config_file)

    decision = await new_router.route(
        task_type="analysis",
        agent_name="compromised_host_analyzer",
        strategy="config_based"
    )
    print(f"  加载后的配置:")
    print(f"    compromised_host_analyzer → {decision.selected_model.name}")

    # 清理
    os.remove(config_file)


async def example_mixed_strategies():
    """示例4：混合使用多种策略"""
    print("\n" + "="*60)
    print("示例4：混合使用多种策略")
    print("="*60)

    router = ModelRouter()

    # 1. 根据场景选择策略
    print("\n4.1 根据场景选择策略")

    # 场景1：已知Agent，使用配置路由
    router.set_agent_model("security_analyzer", "gpt-4o")
    decision1 = await router.route(
        task_type="security_analysis",
        agent_name="security_analyzer",
        strategy="config_based"
    )
    print(f"  场景1 - 已知Agent:")
    print(f"    → 策略: config_based")
    print(f"    → 模型: {decision1.selected_model.name}")

    # 场景2：已知任务类型，使用规则路由
    router.add_rule("translation", "gpt-3.5-turbo")
    decision2 = await router.route(
        task_type="translation",
        strategy="rule_based"
    )
    print(f"  场景2 - 已知任务类型:")
    print(f"    → 策略: rule_based")
    print(f"    → 模型: {decision2.selected_model.name}")

    # 场景3：未知任务，使用智能路由
    decision3 = await router.route(
        task_type="unknown_task",
        task_description="这是一个需要深度推理和代码生成的复杂任务",
        strategy="intelligent"
    )
    print(f"  场景3 - 未知任务:")
    print(f"    → 策略: intelligent")
    print(f"    → 模型: {decision3.selected_model.name}")

    # 2. 带回退的路由
    print("\n4.2 带回退机制的路由")
    decision = await router.route_with_fallback(
        task_type="fallback_test",
        strategies=["config_based", "rule_based", "intelligent"],
        agent_name="non_existent_agent"
    )
    print(f"  使用回退机制:")
    print(f"    → 最终选择: {decision.selected_model.name}")
    print(f"    → 策略: {decision.metadata.get('strategy')}")


async def example_create_llm():
    """示例5：直接创建LLM实例"""
    print("\n" + "="*60)
    print("示例5：为任务创建LLM实例")
    print("="*60)

    router = ModelRouter()

    # 1. 为简单任务创建LLM
    print("\n5.1 为简单任务创建LLM")
    llm = await router.create_llm_for_task(
        task_type="simple_qa",
        complexity=TaskComplexity.SIMPLE,
        temperature=0.7
    )
    print(f"  ✓ 创建了LLM实例: {llm.model_name}")

    # 测试LLM
    from langchain_core.messages import HumanMessage
    try:
        response = await llm.ainvoke([HumanMessage(content="你好，请用一句话介绍自己")])
        print(f"  测试响应: {response.content[:100]}...")
    except Exception as e:
        print(f"  测试失败（可能需要配置API密钥）: {e}")

    # 2. 为复杂任务创建LLM
    print("\n5.2 为复杂任务创建LLM")
    llm = await router.create_llm_for_task(
        task_type="complex_reasoning",
        complexity=TaskComplexity.VERY_COMPLEX,
        agent_name="reasoning_agent",
        temperature=0.3
    )
    print(f"  ✓ 创建了LLM实例: {llm.model_name}")


async def example_model_stats():
    """示例6：查看模型统计"""
    print("\n" + "="*60)
    print("示例6：模型统计信息")
    print("="*60)

    router = ModelRouter()

    # 1. 获取统计信息
    stats = router.get_model_stats()

    print(f"\n总模型数: {stats['total_models']}")

    print("\n按提供商分布:")
    for provider, count in stats['by_provider'].items():
        print(f"  - {provider}: {count} 个模型")

    print("\n成本范围:")
    print(f"  - 最低: ${stats['cost_range']['min']:.4f}/1k tokens")
    print(f"  - 最高: ${stats['cost_range']['max']:.4f}/1k tokens")
    print(f"  - 平均: ${stats['cost_range']['avg']:.4f}/1k tokens")

    print("\n质量范围:")
    print(f"  - 最低: {stats['quality_range']['min']:.1f}/10")
    print(f"  - 最高: {stats['quality_range']['max']:.1f}/10")
    print(f"  - 平均: {stats['quality_range']['avg']:.1f}/10")

    # 2. 列出所有模型
    print("\n所有可用模型:")
    registry = router.registry
    models = registry.list_models()

    for model in sorted(models, key=lambda m: m.cost_per_1k_tokens):
        print(f"  - {model.name:20s} "
              f"质量:{model.quality_score:4.1f} "
              f"速度:{model.speed_score:4.1f} "
              f"成本:${model.cost_per_1k_tokens:.4f}/1k")


async def main():
    """主函数"""
    print("="*60)
    print("模型路由层使用示例")
    print("="*60)

    await example_rule_based_routing()
    await example_intelligent_routing()
    await example_config_based_routing()
    await example_mixed_strategies()
    await example_create_llm()
    await example_model_stats()

    print("\n" + "="*60)
    print("所有示例执行完成")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())