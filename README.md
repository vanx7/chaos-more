# chaos-more

> 作者： @vanx7   
> 项目进展：可行性验证

## 项目介绍
为 [chaos-mesh](https://github.com/chaos-mesh/chaos-mesh) 增加一套基于 eBPF 的插件机制，允许用户实现自定义的故障注入和观测能力

## 背景&动机
混沌工程是我们开发过程中不可忽略的重要步骤，不仅能让我们的程序更健壮，也能让我们对自己的代码有更全面的了解。chaos-mesh 作为云原生领域的混沌工程工具，仅仅定位常见的故障类型是不够的，需要提供给用户更强大的混沌实验的能力，redis、mysql、grpc 等高频应用场景应该补齐。本方案旨在探究基于 eBPF 的自定义故障注入能力的探究，同时有时间的话，补充观测相关的内容，让故障注入前后对比更清晰，解决问题思路更顺畅。

## 项目设计
TODO
