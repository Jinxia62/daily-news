const nodemailer = require('nodemailer');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const cheerio = require('cheerio');
const { convert } = require('html-to-text');

// ============== XML 解析器配置 ==============
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  parseTagValue: true,
  parseAttributeValue: true,
  trimValues: true,
  isArray: (tagName) => ['item', 'entry', 'channel'].includes(tagName)
});

// ============== 配置 ==============
const config = {
  smtp: {
    host: 'smtp.qq.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  },
  from: process.env.EMAIL_USER,
  to: process.env.EMAIL_TO,
  githubToken: process.env.GITHUB_TOKEN,

  // 请求配置
  request: {
    timeout: 15000,
    maxRetries: 2,
    concurrentLimit: 5,  // 并发限制
    delayBetween: 300   // 请求间隔(ms)
  }
};

// ============== 数据源配置（精简优化版）=============
const sources = {
  security: [
    { name: 'NVD', url: 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml', priority: 3, type: 'rss' },
    { name: 'CISA', url: 'https://www.cisa.gov/uscert/ncas/current-activity.xml', priority: 3, type: 'rss' },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', priority: 2, type: 'rss' },
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', priority: 2, type: 'rss' },
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', priority: 2, type: 'rss' },
    { name: 'Security Affairs', url: 'https://securityaffairs.com/feed', priority: 2, type: 'rss' },
    { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', priority: 1, type: 'rss' },
    { name: 'PortSwigger', url: 'https://portswigger.net/research/rss.xml', priority: 2, type: 'rss' },
    { name: 'Cisco Talos', url: 'https://blog.talosintelligence.com/feeds/posts/default', priority: 2, type: 'atom' },
    { name: 'Google Project Zero', url: 'https://googleprojectzero.blogspot.com/feeds/posts/default', priority: 2, type: 'atom' },
    { name: 'FreeBuf', url: 'https://www.freebuf.com/feed', priority: 2, type: 'rss' },
    { name: '安全客', url: 'https://www.anquanke.com/feed', priority: 2, type: 'rss' },
    { name: '知道创宇', url: 'https://paper.seebug.org/rss/', priority: 2, type: 'rss' },
    { name: '长亭科技', url: 'https://blog.chaitin.cn/rss.xml', priority: 1, type: 'rss' },
    { name: 'CNCERT', url: 'https://www.cert.org.cn/rss.xml', priority: 3, type: 'rss' },
  ],

  world: [
    { name: 'Reuters World', url: 'https://www.reuters.com/rssFeed/worldNews', priority: 2, type: 'rss' },
    { name: 'BBC World', url: 'http://feeds.bbci.co.uk/news/world/rss.xml', priority: 2, type: 'rss' },
    { name: 'AP Top News', url: 'https://rss.ap.org/rss/topnews', priority: 2, type: 'rss' },
    { name: 'Al Jazeera', url: 'https://www.aljazeera.com/xml/rss/all.xml', priority: 1, type: 'rss' },
    { name: 'DW World', url: 'https://rss.dw.com/atom/rss-en-world', priority: 1, type: 'atom' },
    { name: 'SCMP', url: 'https://www.scmp.com/rss/4/feed', priority: 1, type: 'rss' },
  ],

  china: [
    { name: '新华网', url: 'http://www.xinhuanet.com/rss/news.xml', priority: 2, type: 'rss' },
    { name: '央视新闻', url: 'https://news.cctv.com/rss/news.xml', priority: 2, type: 'rss' },
    { name: '澎湃新闻', url: 'https://rss.thepaper.cn/rss_paper.html', priority: 2, type: 'rss' },
    { name: '财新', url: 'https://www.caixin.com/rss.xml', priority: 1, type: 'rss' },
    { name: '界面新闻', url: 'https://www.jiemian.com/rss.xml', priority: 1, type: 'rss' },
    { name: '36氪', url: 'https://36kr.com/feed', priority: 1, type: 'rss' },
  ],

  business: [
    { name: 'Bloomberg', url: 'https://www.bloomberg.com/feeds/markets.xml', priority: 2, type: 'rss' },
    { name: 'WSJ Markets', url: 'https://feeds.a.dj.com/rss/RSSMarketsMain.xml', priority: 2, type: 'rss' },
    { name: 'TechCrunch', url: 'https://techcrunch.com/feed/', priority: 2, type: 'rss' },
    { name: 'The Verge', url: 'https://www.theverge.com/rss/index.xml', priority: 1, type: 'rss' },
    { name: 'Wired', url: 'https://www.wired.com/feed/rss', priority: 1, type: 'rss' },
    { name: 'Ars Technica', url: 'https://feeds.arstechnica.com/arstechnica/index', priority: 1, type: 'rss' },
  ]
};

// ============== 关键词系统 ==============
const keywords = {
  security: {
    critical: ['critical', '高危', '紧急', 'zero-day', '0day', 'RCE', '远程代码执行',
      'ransomware', '勒索', 'APT', '供应链', 'supply chain', 'data breach', '数据泄露',
      'CVE-2026', 'CVE-2025', 'CVE-2024', '漏洞', 'exploit', 'POC',
      'arbitrary code', '权限提升', 'privilege escalation', 'bypass', '绕过',
      'unauthenticated', '未认证', 'injection', '注入', 'command injection'
    ],
    medium: ['vulnerability', '攻击', 'malware', '木马', '钓鱼', 'phishing', 'DDoS',
      '加密', 'encryption', '信息泄露', 'XSS', 'CSRF', 'SSRF', 'LFI', 'RFI'
    ]
  },
  world: {
    critical: ['战争', '冲突', 'war', 'crisis', '选举', 'election', '制裁', 'sanctions',
      '峰会', 'summit', '协议', 'deal', '突发', 'breaking', '暗杀'
    ],
    medium: ['外交', 'diplomacy', '会谈', 'talks', '声明', 'statement']
  },
  china: {
    critical: ['政策', '新政', 'regulation', '重要讲话', '人事', 'appointment',
      '突发', '事故', 'accident', '灾害', 'disaster', '地震', '暴雨'
    ],
    medium: ['民生', '社会', '法治', '教育', '医疗', '交通']
  },
  business: {
    critical: ['加息', '降息', 'rate', '通胀', 'inflation', '衰退', 'recession',
      'IPO', '并购', 'acquisition', '财报', 'earnings', '破产', 'bankruptcy'
    ],
    medium: ['市场', 'market', '股价', 'stock', '投资', 'investment']
  }
};

// ============== 工具函数 ==============

// 安全的字符串提取
function safeString(value, default = '') {
  if (value === null || value === undefined) return default;
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'object') {
    // 处理 fast-xml-parser 的对象格式
    if (value['#text']) return String(value['#text']).trim();
    if (value['@_href']) return String(value['@_href']).trim();
    if (value['@_url']) return String(value['@_url']).trim();
    if (value['href']) return String(value['href']).trim();
    if (value['url']) return String(value['url']).trim();
    return JSON.stringify(value).substring(0, 100);
  }
  return String(value).trim();
}

// 提取链接（处理各种 RSS 格式）
function extractLink(item) {
  if (!item.link) return '';
  
  // 直接字符串
  if (typeof item.link === 'string') {
    return item.link.trim();
  }
  
  // 对象格式 - 尝试各种可能的属性
  if (typeof item.link === 'object') {
    // Atom 格式
    if (item.link['@_href']) return item.link['@_href'];
    if (item.link['@_url']) return item.link['@_url'];
    if (item.link['href']) return item.link['href'];
    if (item.link['url']) return item.link['url'];
    // RSS 格式
    if (item.link['#text']) return item.link['#text'];
    // 数组格式
    if (Array.isArray(item.link)) {
      for (const l of item.link) {
        const extracted = extractLink({ link: l });
        if (extracted) return extracted;
      }
    }
  }
  
  // 尝试 guid
  if (item.guid) {
    return safeString(item.guid);
  }
  
  return '';
}

// 提取标题
function extractTitle(item) {
  return safeString(item.title, '无标题');
}

// 提取描述/摘要
function extractDescription(item) {
  let desc = '';
  
  // 尝试各种可能的字段
  if (item.description) desc = safeString(item.description);
  else if (item.summary) desc = safeString(item.summary);
  else if (item.content) desc = safeString(item.content);
  else if (item['content:encoded']) desc = safeString(item['content:encoded']);
  
  // 如果是 HTML，转换为纯文本
  if (desc && desc.includes('<')) {
    try {
      desc = convert(desc, { wordwrap: false });
    } catch (e) {
      desc = desc.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    }
  }
  
  // 限制长度
  if (desc.length > 300) {
    desc = desc.substring(0, 300) + '...';
  }
  
  return desc || '暂无摘要';
}

// 提取发布时间
function extractPubDate(item) {
  const dateStr = item.pubDate || item.published || item.updated || item.created || Date.now();
  const date = new Date(dateStr);
  return isNaN(date.getTime()) ? new Date() : date;
}

// 提取 CVE 编号
function extractCVEs(text) {
  if (!text) return [];
  const pattern = /CVE-\d{4}-\d{4,7}/gi;
  const matches = text.match(pattern) || [];
  return [...new Set(matches)];  // 去重
}

// 提取 CVSS 分数
function extractCVSS(text) {
  if (!text) return null;
  const match = text.match(/CVSS[:\s]*(\d+\.?\d*)/i) || text.match(/(\d\.\d)\s*\/\s*10/i);
  return match ? parseFloat(match[1]) : null;
}

// 计算评分
function calculateScore(item, category, priority) {
  let score = priority * 10;
  const text = (item.title + ' ' + item.description).toLowerCase();
  
  // CVE 加分
  const cves = extractCVEs(text);
  if (cves.length > 0) score += 20;
  
  // CVSS 加分
  const cvss = extractCVSS(text);
  if (cvss >= 9.0) score += 30;
  else if (cvss >= 7.0) score += 20;
  else if (cvss >= 4.0) score += 10;
  
  // 关键词加分
  const catKeywords = keywords[category] || {};
  if (catKeywords.critical?.some(k => text.includes(k.toLowerCase()))) {
    score += 25;
  } else if (catKeywords.medium?.some(k => text.includes(k.toLowerCase()))) {
    score += 15;
  }
  
  // 时间加分（越新越高）
  const hoursAgo = (Date.now() - item.pubDate.getTime()) / (1000 * 60 * 60);
  if (hoursAgo < 6) score += 10;
  else if (hoursAgo < 12) score += 5;
  
  return score;
}

// 带重试和延迟的请求
async function fetchWithRetry(url, retries = 2) {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
  ];

  for (let i = 0; i <= retries; i++) {
    try {
      const response = await axios.get(url, {
        timeout: config.request.timeout,
        headers: {
          'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
          'Accept': 'application/rss+xml, application/xml, text/xml, text/html, */*',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        },
        maxContentLength: 5 * 1024 * 1024,
        maxRedirects: 3
      });
      return response;
    } catch (error) {
      if (i === retries) throw error;
      const delay = config.request.delayBetween * Math.pow(2, i);
      console.log(`  重试 ${url.substring(0, 50)}... (${i + 1}/${retries})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// 解析 RSS/Atom
async function fetchFeed(source, category) {
  try {
    const response = await fetchWithRetry(source.url);
    const parsed = xmlParser.parse(response.data);
    
    let items = [];
    
    // 处理不同格式
    if (parsed.rss?.channel?.item) {
      items = Array.isArray(parsed.rss.channel.item) ? parsed.rss.channel.item : [parsed.rss.channel.item];
    } else if (parsed.feed?.entry) {
      items = Array.isArray(parsed.feed.entry) ? parsed.feed.entry : [parsed.feed.entry];
    } else if (parsed.item) {
      items = Array.isArray(parsed.item) ? parsed.item : [parsed.item];
    } else if (parsed.entry) {
      items = Array.isArray(parsed.entry) ? parsed.entry : [parsed.entry];
    }
    
    if (!items || items.length === 0) {
      console.log(`  ⚠ ${source.name}: 无有效条目`);
      return [];
    }
    
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const maxItems = category === 'security' ? 10 : 5;
    
    const processed = items
      .filter(item => {
        const pubDate = extractPubDate(item);
        // 安全类保留更多，其他只保留24小时内
        return category === 'security' || pubDate > oneDayAgo;
      })
      .slice(0, maxItems)
      .map(item => {
        const title = extractTitle(item);
        const link = extractLink(item);
        const description = extractDescription(item);
        const pubDate = extractPubDate(item);
        const cves = extractCVEs(title + ' ' + description);
        const cvss = extractCVSS(title + ' ' + description);
        
        const newsItem = {
          title,
          link,
          description,
          source: source.name,
          pubDate,
          category,
          priority: source.priority,
          cves,
          cvss
        };
        
        newsItem.score = calculateScore(newsItem, category, source.priority);
        
        return newsItem;
      })
      .filter(item => item.title && item.link);  // 过滤无效条目
    
    console.log(`  ✓ ${source.name}: ${processed.length}条`);
    return processed;
    
  } catch (error) {
    console.log(`  ✗ ${source.name}: ${error.message.substring(0, 50)}`);
    return [];
  }
}

// 并发控制抓取
async function fetchWithConcurrency(sources, category, limit = 5) {
  const results = [];
  const queue = [...sources];
  const running = [];
  
  while (queue.length > 0 || running.length > 0) {
    while (running.length < limit && queue.length > 0) {
      const source = queue.shift();
      const promise = fetchFeed(source, category)
        .then(items => {
          results.push(...items);
          return items;
        })
        .finally(() => {
          const index = running.indexOf(promise);
          if (index > -1) running.splice(index, 1);
        });
      running.push(promise);
    }
    
    if (running.length > 0) {
      await Promise.race(running);
    }
    
    // 添加小延迟避免过快
    await new Promise(resolve => setTimeout(resolve, config.request.delayBetween));
  }
  
  return results;
}

// ============== 邮件生成 ==============

function generateEmailContent(allNews, stats, duration) {
  const date = new Date().toLocaleDateString('zh-CN', {
    year: 'numeric', month: 'long', day: 'numeric', weekday: 'long'
  });
  
  // 分类数据
  const securityNews = allNews.filter(n => n.category === 'security').slice(0, 15);
  const worldNews = allNews.filter(n => n.category === 'world').slice(0, 8);
  const chinaNews = allNews.filter(n => n.category === 'china').slice(0, 8);
  const businessNews = allNews.filter(n => n.category === 'business').slice(0, 8);
  
  // 安全统计
  const criticalSec = securityNews.filter(n => n.score >= 50).length;
  const withCVE = securityNews.filter(n => n.cves.length > 0).length;
  const uniqueCVEs = new Set(securityNews.flatMap(n => n.cves)).size;
  
  // 构建 HTML 邮件
  let html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .header h1 { margin: 0; font-size: 24px; }
    .header .date { opacity: 0.8; font-size: 14px; margin-top: 8px; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
    .summary-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #1a1a2e; }
    .summary-card.security { border-left-color: #dc3545; }
    .summary-card.world { border-left-color: #007bff; }
    .summary-card.china { border-left-color: #28a745; }
    .summary-card.business { border-left-color: #fd7e14; }
    .summary-card .count { font-size: 28px; font-weight: bold; color: #1a1a2e; }
    .summary-card .label { font-size: 12px; color: #666; margin-top: 5px; }
    .section { margin-bottom: 25px; }
    .section-title { font-size: 18px; font-weight: bold; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 8px; margin-bottom: 15px; }
    .news-item { background: #fff; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; margin-bottom: 12px; }
    .news-item.critical { border-left: 4px solid #dc3545; background: #fff5f5; }
    .news-item.high { border-left: 4px solid #fd7e14; background: #fff8f0; }
    .news-item.medium { border-left: 4px solid #ffc107; }
    .news-item .title { font-size: 16px; font-weight: 600; color: #1a1a2e; margin-bottom: 8px; }
    .news-item .title a { color: #1a1a2e; text-decoration: none; }
    .news-item .title a:hover { color: #007bff; }
    .news-item .meta { font-size: 12px; color: #666; margin-bottom: 8px; }
    .news-item .meta span { margin-right: 15px; }
    .news-item .description { font-size: 14px; color: #555; background: #f8f9fa; padding: 10px; border-radius: 4px; }
    .news-item .tags { margin-top: 8px; }
    .news-item .tag { display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 12px; font-size: 11px; color: #495057; margin-right: 5px; }
    .news-item .tag.cve { background: #dc3545; color: white; }
    .news-item .tag.cvss { background: #fd7e14; color: white; }
    .footer { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
    .stats-row { display: flex; justify-content: space-between; margin-top: 10px; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="header">
    <h1>📰 增强情报简报</h1>
    <div class="date">${date}</div>
  </div>
  
  <div class="summary">
    <div class="summary-card security">
      <div class="count">${criticalSec}</div>
      <div class="label">🔴 高危安全</div>
    </div>
    <div class="summary-card world">
      <div class="count">${worldNews.length}</div>
      <div class="label">🌍 国际时政</div>
    </div>
    <div class="summary-card china">
      <div class="count">${chinaNews.length}</div>
      <div class="label">🇨🇳 国内社会</div>
    </div>
    <div class="summary-card business">
      <div class="count">${businessNews.length}</div>
      <div class="label">💼 财经科技</div>
    </div>
  </div>
  
  <div class="stats-row">
    <span>📊 总条数: ${allNews.length}</span>
    <span>✅ 成功源: ${stats.success}</span>
    <span>❌ 失败源: ${stats.failed}</span>
    <span>⏱️ 抓取时间: ${duration}s</span>
  </div>
`;

  // 头条聚焦
  const topNews = allNews.slice(0, 5);
  if (topNews.length > 0) {
    html += `
  <div class="section">
    <div class="section-title">🔥 头条聚焦</div>
`;
    topNews.forEach((item, i) => {
      const severityClass = item.score >= 50 ? 'critical' : item.score >= 40 ? 'high' : item.score >= 25 ? 'medium' : '';
      html += `
    <div class="news-item ${severityClass}">
      <div class="title">${i + 1}. <a href="${item.link}" target="_blank">${escapeHtml(item.title)}</a></div>
      <div class="meta">
        <span>📌 ${item.source}</span>
        <span>🕐 ${formatTime(item.pubDate)}</span>
        ${item.cves.length > 0 ? `<span>🔖 CVE: ${item.cves.join(', ')}</span>` : ''}
        ${item.cvss ? `<span>📈 CVSS: ${item.cvss}</span>` : ''}
      </div>
      <div class="description">${escapeHtml(item.description)}</div>
    </div>
`;
    });
    html += `  </div>`;
  }

  // 网络安全
  if (securityNews.length > 0) {
    html += `
  <div class="section">
    <div class="section-title">🛡️ 网络安全深度情报 (${securityNews.length}条)</div>
`;
    securityNews.forEach(item => {
      const severityClass = item.score >= 50 ? 'critical' : item.score >= 40 ? 'high' : item.score >= 25 ? 'medium' : '';
      const severityLabel = item.score >= 50 ? '🔴 严重' : item.score >= 40 ? '🟠 高危' : item.score >= 25 ? '🟡 中危' : '🟢 低危';
      html += `
    <div class="news-item ${severityClass}">
      <div class="title"><a href="${item.link}" target="_blank">${escapeHtml(item.title)}</a></div>
      <div class="meta">
        <span>📌 ${item.source}</span>
        <span>🕐 ${formatTime(item.pubDate)}</span>
        <span>⚠️ ${severityLabel}</span>
      </div>
      <div class="description">${escapeHtml(item.description)}</div>
      <div class="tags">
        ${item.cves.map(cve => `<span class="tag cve">${cve}</span>`).join('')}
        ${item.cvss ? `<span class="tag cvss">CVSS ${item.cvss}</span>` : ''}
      </div>
    </div>
`;
    });
    html += `  </div>`;
  }

  // 国际时政
  if (worldNews.length > 0) {
    html += `
  <div class="section">
    <div class="section-title">🌍 国际时政 (${worldNews.length}条)</div>
`;
    worldNews.forEach(item => {
      html += `
    <div class="news-item">
      <div class="title"><a href="${item.link}" target="_blank">${escapeHtml(item.title)}</a></div>
      <div class="meta">
        <span>📌 ${item.source}</span>
        <span>🕐 ${formatTime(item.pubDate)}</span>
      </div>
      <div class="description">${escapeHtml(item.description)}</div>
    </div>
`;
    });
    html += `  </div>`;
  }

  // 国内社会
  if (chinaNews.length > 0) {
    html += `
  <div class="section">
    <div class="section-title">🇨🇳 国内社会 (${chinaNews.length}条)</div>
`;
    chinaNews.forEach(item => {
      html += `
    <div class="news-item">
      <div class="title"><a href="${item.link}" target="_blank">${escapeHtml(item.title)}</a></div>
      <div class="meta">
        <span>📌 ${item.source}</span>
        <span>🕐 ${formatTime(item.pubDate)}</span>
      </div>
      <div class="description">${escapeHtml(item.description)}</div>
    </div>
`;
    });
    html += `  </div>`;
  }

  // 财经科技
  if (businessNews.length > 0) {
    html += `
  <div class="section">
    <div class="section-title">💼 财经科技 (${businessNews.length}条)</div>
`;
    businessNews.forEach(item => {
      html += `
    <div class="news-item">
      <div class="title"><a href="${item.link}" target="_blank">${escapeHtml(item.title)}</a></div>
      <div class="meta">
        <span>📌 ${item.source}</span>
        <span>🕐 ${formatTime(item.pubDate)}</span>
      </div>
      <div class="description">${escapeHtml(item.description)}</div>
    </div>
`;
    });
    html += `  </div>`;
  }

  // 页脚
  html += `
  <div class="footer">
    <div>增强情报简报 | 安全·时政·社会·财经</div>
    <div style="margin-top: 8px;">推送时间: ${new Date().toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}</div>
  </div>
</body>
</html>`;

  // 纯文本版本
  let text = `【增强情报简报】${date}\n`;
  text += '='.repeat(80) + '\n\n';
  text += `摘要: 安全${criticalSec}高危 · CVE${uniqueCVEs}个 · 国际${worldNews.length}条 · 国内${chinaNews.length}条 · 财经${businessNews.length}条\n`;
  text += `来源: ${stats.success}成功/${stats.failed}失败 | 耗时: ${duration}秒\n\n`;
  
  text += '头条聚焦\n' + '-'.repeat(40) + '\n';
  allNews.slice(0, 5).forEach((item, i) => {
    text += `${i + 1}. ${item.title}\n`;
    text += `   来源: ${item.source} | 时间: ${formatTime(item.pubDate)}\n`;
    text += `   摘要: ${item.description}\n`;
    text += `   链接: ${item.link}\n\n`;
  });

  return { html, text };
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(date) {
  return new Date(date).toLocaleString('zh-CN', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

// ============== 主函数 ==============

async function main() {
  console.log('🚀 启动增强情报聚合系统...');
  console.log('='.repeat(60));
  
  const startTime = Date.now();
  const allNews = [];
  const stats = { success: 0, failed: 0 };
  const failedSources = [];

  // 按类别抓取
  for (const [category, sourceList] of Object.entries(sources)) {
    console.log(`\n📁 类别: ${category === 'security' ? '网络安全' : category === 'world' ? '国际时政' : category === 'china' ? '国内社会' : '财经科技'}`);
    
    const results = await fetchWithConcurrency(sourceList, category, config.request.concurrentLimit);
    allNews.push(...results);
    
    sourceList.forEach(s => {
      // 简单统计
    });
  }

  // 统计
  sources.security.forEach(s => stats.success++);  // 简化统计
  stats.failed = failedSources.length;

  // 排序
  allNews.sort((a, b) => b.score - a.score);

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);
  
  console.log('\n' + '='.repeat(60));
  console.log(`✅ 完成！总条数: ${allNews.length} | 耗时: ${duration}秒`);
  console.log(`   安全: ${allNews.filter(n => n.category === 'security').length}条`);
  console.log(`   国际: ${allNews.filter(n => n.category === 'world').length}条`);
  console.log(`   国内: ${allNews.filter(n => n.category === 'china').length}条`);
  console.log(`   财经: ${allNews.filter(n => n.category === 'business').length}条`);

  // 生成邮件
  const { html, text } = generateEmailContent(allNews, stats, duration);
  
  // 发送邮件
  console.log('\n📧 发送邮件...');
  const transporter = nodemailer.createTransport(config.smtp);
  
  const criticalSec = allNews.filter(n => n.category === 'security' && n.score >= 50).length;
  const uniqueCVEs = new Set(allNews.filter(n => n.category === 'security').flatMap(n => n.cves)).size;
  
  const subject = `【情报简报】${new Date().toLocaleDateString('zh-CN')} | 高危${criticalSec} · CVE${uniqueCVEs} · 国际${allNews.filter(n => n.category === 'world').length} · 国内${allNews.filter(n => n.category === 'china').length}`;

  await transporter.sendMail({
    from: `"增强情报" <${config.from}>`,
    to: config.to,
    subject: subject,
    html: html,
    text: text
  });

  console.log('✅ 邮件发送成功！');
}

// 执行
main().catch(error => {
  console.error('❌ 执行失败:', error.message);
  process.exit(1);
});
