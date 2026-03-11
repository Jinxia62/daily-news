const nodemailer = require('nodemailer');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const cheerio = require('cheerio');

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (tagName) => ['item', 'entry', 'channel'].includes(tagName)
});

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

  // ========== 网络安全核心源 ==========
  security: {
    // 漏洞预警/搜索引擎
    vulnFeeds: [
      { name: 'CVE Feed', url: 'https://cve.circl.lu/feeds/rss.xml', priority: 1 },
      { name: 'NVD', url: 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml', priority: 1 },
      { name: 'CISA KEV', url: 'https://www.cisa.gov/uscert/ncas/current-activity.xml', priority: 1 },
      { name: 'MSRC', url: 'https://msrc.microsoft.com/blog/rss', priority: 1 },
      { name: 'CVE Details', url: 'https://www.cvedetails.com/rss.php', priority: 1 },
      { name: 'Exploit-DB', url: 'https://www.exploit-db.com/rss.xml', priority: 1 },
      { name: 'Vulmon', url: 'https://vulmon.com/searchpage?q=*&sortby=bydate', type: 'html', priority: 1 },
    ],

    // 安全新闻媒体
    newsMedia: [
      { name: 'The Hacker Wire', url: 'https://www.thehackerwire.com/security-news/index.xml', priority: 1 },
      { name: 'Security Affairs', url: 'https://securityaffairs.com/feed', priority: 1 },
      { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', priority: 1 },
      { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', priority: 1 },
      { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', priority: 1 },
      { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', priority: 2 },
      { name: 'ThreatPost', url: 'https://threatpost.com/feed/', priority: 2 },
    ],

    // 技术研究/深度分析
    research: [
      { name: 'GitHub Advisories', url: 'https://github.com/advisories.rss', priority: 1 },
      { name: 'GitHub Advisories API', url: 'https://api.github.com/advisories', type: 'api', priority: 1 },
      { name: 'Google Project Zero', url: 'https://googleprojectzero.blogspot.com/feeds/posts/default', type: 'atom', priority: 1 },
      { name: 'Cisco Talos', url: 'https://blog.talosintelligence.com/feeds/posts/default', type: 'atom', priority: 1 },
      { name: 'Cloudflare Blog', url: 'https://blog.cloudflare.com/rss/', priority: 2 },
      { name: 'SANS ISC', url: 'https://isc.sans.edu/rssfeed.xml', priority: 2 },
      { name: 'PortSwigger Research', url: 'https://portswigger.net/research/rss.xml', priority: 2 },
    ],

    // 国内安全
    chinaSec: [
      { name: 'CNNVD', url: 'http://www.cnnvd.org.cn/web/cnnvd/rssxml/CNNVD.xml', priority: 1 },
      { name: 'CNCERT', url: 'https://www.cert.org.cn/rss.xml', priority: 1 },
      { name: '安全客', url: 'https://www.anquanke.com/feed', priority: 1 },
      { name: 'FreeBuf', url: 'https://www.freebuf.com/feed', priority: 1 },
      { name: '嘶吼', url: 'https://www.4hou.com/feed', priority: 2 },
      { name: '看雪学院', url: 'https://www.kanxue.com/rss.xml', priority: 2 },
      { name: '知道创宇 Paper', url: 'https://paper.seebug.org/rss/', priority: 1 },
      { name: '长亭科技', url: 'https://blog.chaitin.cn/rss.xml', priority: 2 },
    ],

    // 威胁情报/黑产追踪
    threatIntel: [
      { name: 'Ransomware Tracker', url: 'https://ransomwaretracker.abuse.ch/feeds/csv/', type: 'csv', priority: 1 },
      { name: 'URLhaus', url: 'https://urlhaus.abuse.ch/feeds/rss/', priority: 2 },
      { name: 'Feodo Tracker', url: 'https://feodotracker.abuse.ch/feeds/rss/', priority: 2 },
      { name: 'Cybercrime Tracker', url: 'https://cybercrime-tracker.net/rss.xml', priority: 2 },
    ]
  },

  // 国际时政
  world: {
    international: [
      { name: 'Reuters World', url: 'https://www.reuters.com/rssFeed/worldNews', priority: 1 },
      { name: 'BBC World', url: 'http://feeds.bbci.co.uk/news/world/rss.xml', priority: 1 },
      { name: 'AP Top News', url: 'https://rss.ap.org/rss/topnews', priority: 1 },
      { name: 'CNN World', url: 'http://rss.cnn.com/rss/edition_world.rss', priority: 2 },
      { name: 'Al Jazeera', url: 'https://www.aljazeera.com/xml/rss/all.xml', priority: 2 },
      { name: 'DW News', url: 'https://rss.dw.com/atom/rss-en-world', type: 'atom', priority: 2 }
    ],
    regions: [
      { name: 'SCMP (亚洲)', url: 'https://www.scmp.com/rss/4/feed', priority: 2 },
      { name: 'The Moscow Times', url: 'https://www.themoscowtimes.com/rss/news', priority: 2 },
      { name: 'Middle East Eye', url: 'https://www.middleeasteye.net/rss.xml', priority: 2 },
    ],
    chinaView: [
      { name: 'FT China', url: 'https://www.ft.com/china?format=rss', priority: 1 },
      { name: 'Bloomberg China', url: 'https://www.bloomberg.com/feeds/china.xml', priority: 1 },
      { name: 'NYT China', url: 'https://rss.nytimes.com/services/xml/rss/nyt/China.xml', priority: 1 },
      { name: 'WSJ China', url: 'https://feeds.a.dj.com/rss/RSSChina.xml', priority: 2 },
    ]
  },

  // 国内社会
  china: {
    official: [
      { name: '新华网', url: 'http://www.xinhuanet.com/rss/news.xml', priority: 1 },
      { name: '人民网', url: 'http://rss.people.com.cn/rmrb/2d09e656329c4089a7f4370cd38d10f8.rss', priority: 1 },
      { name: '央视新闻', url: 'https://news.cctv.com/rss/news.xml', priority: 1 },
      { name: '环球网', url: 'https://world.huanqiu.com/rss.xml', priority: 2 },
    ],
    portals: [
      { name: '澎湃新闻', url: 'https://rss.thepaper.cn/rss_paper.html', priority: 1 },
      { name: '财新网', url: 'https://www.caixin.com/rss.xml', priority: 1 },
      { name: '界面新闻', url: 'https://www.jiemian.com/rss.xml', priority: 2 },
      { name: '观察者网', url: 'https://www.guancha.cn/rss.xml', priority: 2 }
    ],
    local: [
      { name: '南方周末', url: 'https://www.infzm.com/rss', priority: 2 },
      { name: '新京报', url: 'https://www.bjnews.com.cn/rss.xml', priority: 2 },
    ]
  },

  // 财经科技
  business: {
    finance: [
      { name: 'WSJ', url: 'https://feeds.a.dj.com/rss/RSSMarketsMain.xml', priority: 1 },
      { name: 'FT', url: 'https://www.ft.com/markets?format=rss', priority: 1 },
      { name: 'Bloomberg', url: 'https://www.bloomberg.com/feeds/markets.xml', priority: 1 },
      { name: 'Reuters Business', url: 'https://www.reuters.com/rssFeed/businessNews', priority: 2 },
      { name: 'CNBC', url: 'https://www.cnbc.com/id/10001147/device/rss/rss.html', priority: 2 }
    ],
    tech: [
      { name: 'TechCrunch', url: 'https://techcrunch.com/feed/', priority: 1 },
      { name: 'The Verge', url: 'https://www.theverge.com/rss/index.xml', priority: 2 },
      { name: 'Wired', url: 'https://www.wired.com/feed/rss', priority: 2 },
      { name: 'Ars Technica', url: 'https://feeds.arstechnica.com/arstechnica/index', priority: 2 },
      { name: '36氪', url: 'https://36kr.com/feed', priority: 1 },
      { name: '虎嗅', url: 'https://www.huxiu.com/rss/', priority: 1 }
    ]
  }
};

// 智能关键词系统
const keywords = {
  security: {
    critical: [
      'critical', '高危', '紧急', 'zero-day', '0day', 'RCE', '远程代码执行',
      'ransomware', '勒索', 'APT', '供应链', 'supply chain', 'data breach', '数据泄露',
      'CVE-2026', 'CVE-2025', '漏洞', 'exploit', 'POC', 'proof of concept',
      'arbitrary code', '权限提升', 'privilege escalation', 'bypass', '绕过',
      'unauthenticated', '未认证', 'injection', '注入', 'command injection', '命令注入'
    ],
    medium: [
      'vulnerability', '攻击', 'malware', '木马', '钓鱼', 'phishing', 'DDoS',
      '加密', 'encryption', '信息泄露', 'XSS', 'CSRF', 'SSRF', 'LFI', 'RFI',
      'Directory traversal', '路径遍历', 'Buffer overflow', '缓冲区溢出'
    ]
  },
  world: {
    critical: ['战争', '冲突', 'war', 'crisis', '选举', 'election', '制裁', 'sanctions',
               '峰会', 'summit', '协议', 'deal', '突发', 'breaking', 'assassination', '暗杀'],
    medium: ['外交', 'diplomacy', '会谈', 'talks', '声明', 'statement']
  },
  china: {
    critical: ['政策', '新政', 'regulation', '重要讲话', '人事', 'appointment',
               '突发', '事故', 'accident', '灾害', 'disaster', '地震', '暴雨'],
    medium: ['民生', '社会', '法治', '教育', '医疗', '交通']
  },
  business: {
    critical: ['加息', '降息', 'rate', '通胀', 'inflation', '衰退', 'recession',
               'IPO', '并购', 'acquisition', '财报', 'earnings', '破产', 'bankruptcy'],
    medium: ['市场', 'market', '股价', 'stock', '投资', 'investment']
  }
};

// 核心工具函数

// 带智能重试的fetch
async function fetchWithRetry(url, retries = 3, timeout = 10000) {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
  ];

  for (let i = 0; i <= retries; i++) {
    try {
      const response = await axios.get(url, {
        timeout,
        headers: {
          'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
          'Accept': 'application/rss+xml, application/xml, text/xml, text/html, */*',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        },
        maxContentLength: 10 * 1024 * 1024,
        maxRedirects: 5
      });
      return response;
    } catch (error) {
      if (i === retries) throw error;
      const delay = 2000 * Math.pow(2, i) + Math.random() * 1000;
      console.log(`重试 ${url} (${i + 1}/${retries}) 等待 ${Math.round(delay/1000)}秒`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// 解析RSS/Atom
async function fetchRSS(source, category, subCategory) {
  try {
    const response = await fetchWithRetry(source.url);
    const parsed = xmlParser.parse(response.data);

    let items = [];
    if (parsed.rss?.channel?.item) {
      items = parsed.rss.channel.item;
    } else if (parsed.feed?.entry) {
      items = parsed.feed.entry;
    } else if (Array.isArray(parsed)) {
      items = parsed;
    }

    if (!items || items.length === 0) return [];

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    return items
      .filter(item => {
        const pubDate = new Date(item.pubDate || item.updated || item.published || 0);
        return pubDate > oneDayAgo || category === 'security';
      })
      .slice(0, category === 'security' ? 5 : 3)
      .map(item => {
        let title = item.title || '无标题';
        let description = item.description || item.summary || item.content || '';
        const link = item.link || (item.link && item.link['@_href']) || item.guid || source.url;
        const pubDate = new Date(item.pubDate || item.updated || item.published);

        // 确保title和description是字符串
        title = typeof title === 'string' ? title : String(title);
        description = typeof description === 'string' ? description : String(description);

        let score = source.priority * 5;
        const text = (title + ' ' + description).toLowerCase();

        const cves = extractCVEs(title + ' ' + description);
        if (cves.length > 0) score += 15;

        const catKeywords = keywords[category] || {};
        if (catKeywords.critical?.some(k => text.includes(k.toLowerCase()))) {
          score += 20;
        } else if (catKeywords.medium?.some(k => text.includes(k.toLowerCase()))) {
          score += 10;
        }

        return {
          title: title.replace(/\s+/g, ' ').trim(),
          description: description.replace(/\s+/g, ' ').trim().substring(0, 200),
          link,
          source: source.name,
          pubDate,
          score,
          category,
          subCategory,
          cves
        };
      });

  } catch (error) {
    console.error(`获取 ${source.name} 失败:`, error.message);
    return [];
  }
}

// 解析Vulmon HTML页面
async function fetchVulmon(source, category, subCategory) {
  try {
    const response = await fetchWithRetry(source.url);
    const $ = cheerio.load(response.data);

    const items = [];
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // Vulmon页面结构：查找最近的漏洞条目
    $('.vuln-row, .search-result, tr').each((index, element) => {
      if (items.length >= 10) return false;

      const $el = $(element);
      const titleEl = $el.find('.vuln-title, a[href*="CVE"]').first();

      if (titleEl.length > 0) {
        let title = titleEl.text().trim();
        const link = titleEl.attr('href');
        const fullLink = link ? (link.startsWith('http') ? link : `https://vulmon.com${link}`) : source.url;

        // 确保title是字符串
        title = typeof title === 'string' ? title : String(title);

        const cveMatch = title.match(/CVE-\d{4}-\d{4,7}/);
        const cves = cveMatch ? [cveMatch[0]] : [];

        // 提取CVSS分数
        const cvssText = $el.find('.cvss-score, .score').first().text().trim();
        const cvssMatch = cvssText.match(/(\d+\.?\d*)/);
        const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : null;

        // 提取描述
        const description = $el.find('.vuln-desc, .description, td:nth-child(2)').first().text().trim().substring(0, 200);

        let score = source.priority * 5;
        if (cves.length > 0) score += 15;
        if (cvss && cvss >= 7.0) score += 20;
        else if (cvss && cvss >= 4.0) score += 10;

        items.push({
          title: title.replace(/\s+/g, ' ').trim(),
          description: description || title,
          link: fullLink,
          source: source.name,
          pubDate: new Date(),
          score,
          category,
          subCategory,
          cves,
          cvss
        });
      }
    });

    return items;
  } catch (error) {
    console.error(`获取 ${source.name} 失败:`, error.message);
    return [];
  }
}

// 解析GitHub Advisories API
async function fetchGitHubAdvisories(source, category, subCategory) {
  try {
    const response = await fetchWithRetry(`${source.url}?per_page=20&sort=published&direction=desc`);

    if (!Array.isArray(response.data)) {
      return [];
    }

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    return response.data
      .filter(advisory => {
        const pubDate = new Date(advisory.published_at || advisory.created_at);
        return pubDate > oneDayAgo;
      })
      .slice(0, 10)
      .map(advisory => {
        let title = advisory.title || '无标题';
        let description = advisory.description || advisory.summary || '';
        const severity = advisory.severity || advisory.cvss?.score || null;

        // 确保title和description是字符串
        title = typeof title === 'string' ? title : String(title);
        description = typeof description === 'string' ? description : String(description);

        let score = source.priority * 5;
        const text = (title + ' ' + description).toLowerCase();

        const cves = advisory.cves?.map(c => c.id) || [];
        if (cves.length > 0) score += 15;

        if (severity === 'critical' || (advisory.cvss?.score && advisory.cvss.score >= 9.0)) {
          score += 30;
        } else if (severity === 'high' || (advisory.cvss?.score && advisory.cvss.score >= 7.0)) {
          score += 20;
        } else if (severity === 'medium' || (advisory.cvss?.score && advisory.cvss.score >= 4.0)) {
          score += 10;
        }

        const catKeywords = keywords[category] || {};
        if (catKeywords.critical?.some(k => text.includes(k.toLowerCase()))) {
          score += 20;
        } else if (catKeywords.medium?.some(k => text.includes(k.toLowerCase()))) {
          score += 10;
        }

        return {
          title: title.replace(/\s+/g, ' ').trim(),
          description: description.replace(/\s+/g, ' ').trim().substring(0, 200),
          link: advisory.html_url || advisory.url || source.url,
          source: `${source.name} - ${advisory.package || 'Unknown'}`,
          pubDate: new Date(advisory.published_at || advisory.created_at),
          score,
          category,
          subCategory,
          cves,
          cvss: advisory.cvss?.score,
          severity: advisory.severity
        };
      });

  } catch (error) {
    console.error(`获取 ${source.name} 失败:`, error.message);
    return [];
  }
}

// 解析CSV
async function fetchCSV(source, category, subCategory) {
  try {
    const response = await fetchWithRetry(source.url);
    const lines = response.data.split('\n').slice(1, 10);

    return lines
      .filter(line => line.trim())
      .map(line => {
        const fields = line.split(',');
        return {
          title: `威胁情报: ${fields[1] || '未知'}`,
          description: `类型: ${fields[2] || '未知'}, 时间: ${fields[0] || '未知'}`,
          link: fields[3] || source.url,
          source: source.name,
          pubDate: new Date(),
          score: 50,
          category,
          subCategory,
          cves: []
        };
      });
  } catch (error) {
    console.error(`获取 ${source.name} CSV 失败:`, error.message);
    return [];
  }
}

// 提取CVE编号
function extractCVEs(text) {
  const cvePattern = /CVE-\d{4}-\d{4,7}/g;
  return (text.match(cvePattern) || []).filter((v, i, a) => a.indexOf(v) === i);
}

// 分析引擎

// 生成安全简报
function generateSecurityBrief(securityNews) {
  const critical = securityNews.filter(n => n.score >= 40);
  const withCVE = securityNews.filter(n => n.cves.length > 0);
  const withCVSS = securityNews.filter(n => n.cvss && n.cvss > 0);

  const cveMap = new Map();
  securityNews.forEach(n => {
    n.cves.forEach(cve => {
      if (!cveMap.has(cve)) cveMap.set(cve, []);
      cveMap.get(cve).push(n.source);
    });
  });

  // 按来源统计
  const sourceStats = {};
  securityNews.forEach(n => {
    sourceStats[n.source] = (sourceStats[n.source] || 0) + 1;
  });

  // 按严重级别统计
  const severityStats = {
    critical: securityNews.filter(n => n.severity === 'critical' || n.score >= 50).length,
    high: securityNews.filter(n => n.severity === 'high' || (n.score >= 40 && n.score < 50)).length,
    medium: securityNews.filter(n => n.severity === 'medium' || (n.score >= 25 && n.score < 40)).length,
    low: securityNews.filter(n => n.severity === 'low' || n.score < 25).length
  };

  // 统计CVSS分布
  const cvssStats = {
    critical: withCVSS.filter(n => n.cvss >= 9.0).length,
    high: withCVSS.filter(n => n.cvss >= 7.0 && n.cvss < 9.0).length,
    medium: withCVSS.filter(n => n.cvss >= 4.0 && n.cvss < 7.0).length,
    low: withCVSS.filter(n => n.cvss < 4.0).length
  };

  return {
    criticalCount: critical.length,
    totalWithCVE: withCVE.length,
    uniqueCVEs: cveMap.size,
    totalWithCVSS: withCVSS.length,
    topCVEs: Array.from(cveMap.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, 5)
      .map(([cve, sources]) => ({ cve, sources: sources.length })),
    topSources: Object.entries(sourceStats)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5),
    severityStats,
    cvssStats
  };
}

// 生成综合简报
function generateBrief(allNews) {
  const byCategory = {
    security: allNews.filter(n => n.category === 'security'),
    world: allNews.filter(n => n.category === 'world'),
    china: allNews.filter(n => n.category === 'china'),
    business: allNews.filter(n => n.category === 'business')
  };

  return {
    security: generateSecurityBrief(byCategory.security),
    world: { total: byCategory.world.length },
    china: { total: byCategory.china.length },
    business: { total: byCategory.business.length },
    total: allNews.length
  };
}

// 主函数
async function main() {
  console.log('启动增强版情报聚合系统...');
  console.log('='.repeat(70));

  const startTime = Date.now();
  const allNews = [];
  const failedSources = [];
  const sourceStats = { success: 0, failed: 0 };

  for (const [category, subCategories] of Object.entries(config)) {
    if (category === 'smtp' || category === 'from' || category === 'to') continue;

    console.log(`\n类别: ${category === 'security' ? '网络安全' :
                                   category === 'world' ? '国际时政' :
                                   category === 'china' ? '国内社会' :
                                   category === 'business' ? '财经科技' : category}`);

    for (const [subCategory, sources] of Object.entries(subCategories)) {
      console.log(`  ${subCategory} (${sources.length}个源)`);

      const promises = sources.map(async source => {
        try {
          let items;
          if (source.type === 'csv') {
            items = await fetchCSV(source, category, subCategory);
          } else if (source.type === 'api') {
            items = await fetchGitHubAdvisories(source, category, subCategory);
          } else if (source.type === 'html') {
            items = await fetchVulmon(source, category, subCategory);
          } else {
            items = await fetchRSS(source, category, subCategory);
          }
          sourceStats.success++;
          return items;
        } catch (error) {
          sourceStats.failed++;
          failedSources.push(source.name);
          return [];
        }
      });

      const results = await Promise.allSettled(promises);
      results.forEach((result) => {
        if (result.status === 'fulfilled') {
          allNews.push(...result.value);
        }
      });
    }
  }

  // 按分数排序
  allNews.sort((a, b) => b.score - a.score);

  // 生成简报
  const brief = generateBrief(allNews);

  // 分类整理
  const securityNews = allNews.filter(n => n.category === 'security').slice(0, 20);
  const worldNews = allNews.filter(n => n.category === 'world').slice(0, 10);
  const chinaNews = allNews.filter(n => n.category === 'china').slice(0, 10);
  const businessNews = allNews.filter(n => n.category === 'business').slice(0, 8);

  // 构建邮件
  const date = new Date().toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    weekday: 'long'
  });

  let content = `【增强情报简报】${date}\n`;
  content += '='.repeat(80) + '\n\n';

  // 执行摘要
  content += `今日情报摘要\n`;
  content += `${'-'.repeat(40)}\n`;
  content += `网络安全: ${brief.security.criticalCount}个高危 · ${brief.security.uniqueCVEs}个CVE · ${brief.security.totalWithCVE}条含CVE\n`;
  content += `国际时政: ${brief.world.total}条\n`;
  content += `国内社会: ${brief.china.total}条\n`;
  content += `财经科技: ${brief.business.total}条\n`;
  content += `情报来源: ${sourceStats.success}个成功, ${sourceStats.failed}个失败\n`;
  content += `抓取时间: ${((Date.now() - startTime)/1000).toFixed(1)}秒\n\n`;

  // 头条聚焦
  content += `头条聚焦\n`;
  content += `${'-'.repeat(40)}\n`;
  allNews.slice(0, 5).forEach((item, i) => {
    const icons = { security: '网络安全', world: '国际', china: '国内', business: '财经' };
    content += `${i+1}. [${icons[item.category]}] ${item.title}\n`;
    content += `   来源: ${item.source}`;
    if (item.cves.length > 0) content += ` | CVE: ${item.cves.join(', ')}`;
    if (item.cvss) content += ` | CVSS: ${item.cvss}`;
    content += `\n   链接: ${item.link}\n\n`;
  });

  // 网络安全深度情报
  if (securityNews.length > 0) {
    content += `网络安全深度情报 (${securityNews.length}条)\n`;
    content += `${'-'.repeat(40)}\n`;
    securityNews.forEach((item, i) => {
      const severity = item.score >= 50 ? '[严重]' : item.score >= 40 ? '[高危]' : item.score >= 25 ? '[中危]' : '[低危]';
      content += `${severity} ${i+1}. ${item.title}\n`;
      content += `   来源: ${item.source}`;
      if (item.cves.length > 0) content += ` | CVE: ${item.cves.join(', ')}`;
      if (item.cvss) content += ` | CVSS: ${item.cvss}`;
      content += `\n   描述: ${item.description}\n`;
      content += `   链接: ${item.link}\n\n`;
    });
  }

  // 国际时政
  if (worldNews.length > 0) {
    content += `国际时政 (${worldNews.length}条)\n`;
    content += `${'-'.repeat(40)}\n`;
    worldNews.forEach((item, i) => {
      content += `${i+1}. ${item.title}\n`;
      content += `   来源: ${item.source}\n`;
      content += `   链接: ${item.link}\n\n`;
    });
  }

  // 国内社会
  if (chinaNews.length > 0) {
    content += `国内社会 (${chinaNews.length}条)\n`;
    content += `${'-'.repeat(40)}\n`;
    chinaNews.forEach((item, i) => {
      content += `${i+1}. ${item.title}\n`;
      content += `   来源: ${item.source}\n`;
      content += `   链接: ${item.link}\n\n`;
    });
  }

  // 财经科技
  if (businessNews.length > 0) {
    content += `财经科技 (${businessNews.length}条)\n`;
    content += `${'-'.repeat(40)}\n`;
    businessNews.forEach((item, i) => {
      content += `${i+1}. ${item.title}\n`;
      content += `   来源: ${item.source}\n`;
      content += `   链接: ${item.link}\n\n`;
    });
  }

  // 安全情报统计
  content += `安全情报深度分析\n`;
  content += `${'-'.repeat(40)}\n`;
  content += `严重级别分布: ${brief.security.severityStats.critical}严重 · ${brief.security.severityStats.high}高危 · ${brief.security.severityStats.medium}中危 · ${brief.security.severityStats.low}低危\n`;
  content += `涉及CVE: ${brief.security.uniqueCVEs}个\n`;
  if (brief.security.topCVEs.length > 0) {
    content += `热门CVE: ${brief.security.topCVEs.map(c => `${c.cve}(${c.sources}个源)`).join(', ')}\n`;
  }
  content += `活跃源: ${brief.security.topSources.map(s => `${s[0]}(${s[1]}条)`).join(', ')}\n\n`;

  // 失败源
  if (failedSources.length > 0) {
    content += `暂时不可用 (${failedSources.length}个):\n`;
    content += failedSources.slice(0, 10).join('、');
    if (failedSources.length > 10) content += ` 等`;
    content += '\n\n';
  }

  content += '='.repeat(80) + '\n';
  content += `推送时间: ${new Date().toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}\n`;
  content += `增强情报简报 | 安全·时政·社会·财经\n`;
  content += `GitHub Advisories: https://github.com/advisories\n`;

  // 发送邮件
  const transporter = nodemailer.createTransport(config.smtp);
  await transporter.verify();

  const subject = `【增强简报】${date} | 高危${brief.security.criticalCount} · CVE${brief.security.uniqueCVEs} · 国际${brief.world.total} · 国内${brief.china.total}`;

  const info = await transporter.sendMail({
    from: `"增强情报" <${config.from}>`,
    to: config.to,
    subject: subject,
    text: content
  });

  console.log('\n增强情报推送成功！');
  console.log('邮件ID:', info.messageId);
  console.log(`总条数: ${allNews.length}条, 成功源: ${sourceStats.success}, 失败源: ${sourceStats.failed}`);
  console.log(`安全情报: ${brief.security.criticalCount}严重, ${brief.security.uniqueCVEs}CVE, ${brief.security.totalWithCVE}条含CVE`);
}

// 执行
main().catch(error => {
  console.error('执行失败:', error);
  if (error.response) {
    console.error('状态码:', error.response.status);
    console.error('响应头:', error.response.headers);
  }
  process.exit(1);
});
