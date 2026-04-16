---
layout: book
title: "The Diabolical eBPF Field Manual"
---
## eBPF is All You Need

> "When they gave us eBPF, they handed us the keys to the kingdom. Now we're redecorating."

Welcome to the dark side of kernel programming. This field manual documents techniques that transform eBPF—a "safe" kernel programming interface—into a powerful arsenal for breaking isolation, bypassing security controls, and maintaining persistent access to systems that were never meant to be compromised. 

Each technique in this collection demonstrates how a single misconfiguration can turn eBPF from a monitoring tool into a perfect attack primitive.

## Table of Contents

{% assign sorted_posts = site.posts | reverse %}
{% for post in sorted_posts %}
* [{{ post.title }}]({{ site.baseurl }}{{ post.url }}) - {{ post.date | date: "%B %d, %Y" }}
{% endfor %}

*Remember: With great power comes great responsibility. These techniques are documented for defensive awareness.*
