import 'dart:convert' show base64, utf8;
import 'dart:math' as math;

import '../core/knowledge.dart';
import '../core/models.dart';
import '../core/psl_data.dart' show kPslSnapshotDate;
import 'public_suffix.dart';
import 'text_utils.dart';
import 'url_evasion.dart';
import 'url_normalizer.dart';
import 'url_report.dart';
import 'url_validator.dart';

class _Run {
  const _Run(this.result, this.norm);
  final ScanResult result;
  final NormalizedUrl? norm;
}

/// وجهة مخبّأة جوه باراميتر إعادة توجيه (url / next / redirect ...).
class _RedirectTarget {
  const _RedirectTarget(this.url, this.encoded);
  final String url;

  /// الوجهة كانت مخبّأة بترميز base64 (مش مكتوبة كرابط صريح).
  final bool encoded;
}

/// كلمات عربية لقيناها في مسار/استعلام الرابط.
class _ArHits {
  const _ArHits(this.cred, this.general);
  final List<String> cred;
  final List<String> general;
}

/// محلل الروابط: كله يعمل على الجهاز بدون اتصال بالإنترنت.
/// كل فحص بيضيف "نقاط خطر"، والمجموع (0-100) يحدد المستوى.
class UrlAnalyzer {
  UrlAnalyzer._();

  static final RegExp _embedded = RegExp(r'https?://', caseSensitive: false);
  static const List<String> _credWords = <String>[
    'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'password', 'passwd', 'otp', 'confirm', 'validate', 'authenticate',
    'unlock', 'recover', 'restore',
  ];
  static final RegExp _redirectValue =
      RegExp(r'^(https?:)?//', caseSensitive: false);

  static final RegExp _ipv4Like = RegExp(r'^[0-9.]+$');

  /// الدومين المسجّل (Registrable Domain) حسب Public Suffix List: اللاحقة العامة + جزء
  /// واحد (example.co.uk / evil.github.io). لو المضيف IP أو هو نفسه لاحقة عامة (com،
  /// co.uk) بنرجّعه كما هو. المطابقة على الأجزاء بعد فك xn-- (القواعد Unicode).
  static String registrableDomain(String host) {
    var h = host.trim().toLowerCase();
    while (h.endsWith('.')) {
      h = h.substring(0, h.length - 1);
    }
    if (h.isEmpty || h.contains(':') || _ipv4Like.hasMatch(h)) return h;
    final labels = h.split('.');
    final uni = labels
        .map((l) => l.startsWith('xn--')
            ? (UrlNormalizer.decodePunycode(l.substring(4)) ?? l)
            : l)
        .join('.');
    final m = PublicSuffixList.instance.lookup(uni);
    if (m == null || !m.hasRegistrable || m.labels.length != labels.length) {
      return h;
    }
    return labels.sublist(labels.length - m.suffixLength - 1).join('.');
  }

  static Brand? _officialOf(String host) => officialBrandOf(host);

  /// نطاق إقليمي لعلامة كبيرة (google.de / amazon.co.uk): label.cctld
  static Brand? _regionalOf(String domain, String tld) {
    if (tld.length != 2 || kRiskyTlds.contains(tld) || kAbusedCc.contains(tld)) {
      return null;
    }
    final label = domain.split('.').first;
    for (final b in kBrands) {
      if (b.regional && b.keys.contains(label)) return b;
    }
    return null;
  }

  /// مضيف مشترك (مختصِر روابط / استضافة مجانية / دومين علامة رسمية):
  /// لا نحكم عليه كله بسبب رابط واحد مدرج في قائمة تهديدات.
  static bool isSharedHost(String host) {
    if (kShorteners.contains(host)) return true;
    for (final d in kFreeHosts) {
      if (host == d || host.endsWith('.$d')) return true;
    }
    return _officialOf(host) != null;
  }

  static int _lev(String a, String b) {
    if (a == b) return 0;
    if (a.isEmpty) return b.length;
    if (b.isEmpty) return a.length;
    var prev = List<int>.generate(b.length + 1, (i) => i);
    for (var i = 1; i <= a.length; i++) {
      final cur = List<int>.filled(b.length + 1, 0);
      cur[0] = i;
      for (var j = 1; j <= b.length; j++) {
        final cost = a.codeUnitAt(i - 1) == b.codeUnitAt(j - 1) ? 0 : 1;
        cur[j] = math.min(
          math.min(cur[j - 1] + 1, prev[j] + 1),
          prev[j - 1] + cost,
        );
      }
      prev = cur;
    }
    return prev[b.length];
  }

  /// يحوّل الأرقام والحروف المتشابهة لحروفها (paypa1 -> paypal)
  static List<String> _deob(String t) {
    String conv(String s, String one) => s
        .replaceAll('rn', 'm')
        .replaceAll('vv', 'w')
        .replaceAll('0', 'o')
        .replaceAll('1', one)
        .replaceAll('3', 'e')
        .replaceAll('4', 'a')
        .replaceAll('5', 's')
        .replaceAll('7', 't')
        .replaceAll('\$', 's');
    return <String>[conv(t, 'l'), conv(t, 'i')];
  }

  /// اسم يبدو مولَّدًا عشوائيًا (مثل xkqzrtvbnm أو a8392kd04x1): شائع في
  /// الدومينات المؤقتة اللي تستخدمها حملات الاحتيال. حذر عمدًا لتقليل الإنذارات الكاذبة.
  static bool _looksRandom(String label) {
    if (label.length < 10) return false;
    if (!RegExp(r'^[a-z0-9]+$').hasMatch(label)) return false;
    // سلسلة حروف ساكنة طويلة (الإنجليزية العادية نادرًا تتعدى 6)
    if (RegExp(r'[bcdfghjklmnpqrstvwxz]{7,}').hasMatch(label)) return true;
    // حروف وأرقام متداخلة بكثرة
    final digits = RegExp(r'\d').allMatches(label).length;
    if (label.length >= 12 &&
        digits >= 4 &&
        RegExp(r'[a-z]\d+[a-z]').hasMatch(label)) {
      return true;
    }
    return false;
  }

  static ScanResult _finish(List<Finding> f, UrlParts? parts, String title,
      {bool partial = false}) {
    // الدرجة بطريقة موحدة: كل إشارة بكودها مرة واحدة، والإشارات الضعيفة ليها سقف.
    final total = aggregateScore(f);
    f.sort((a, b) => b.points.compareTo(a.points));
    return ScanResult(
      kind: ScanKind.url,
      score: total,
      findings: f,
      parts: parts,
      title: title,
      partial: partial,
    );
  }

  /// يحلل رابطًا ويرجّع [ScanResult] (الواجهة القديمة، بدون تغيير في الاستخدام).
  static ScanResult analyze(String input) => _run(input).result;

  /// نفس التحليل لكن بتقرير منظم: الدرجة، المستوى (آمن/مشبوه/خطير)، الرابط بعد
  /// التنظيف، وقايمة الإشارات بشرح ووزن كل واحدة.
  static UrlThreatReport report(String input) {
    final run = _run(input);
    return UrlThreatReport.from(input, run.result, run.norm);
  }

  static _Run _run(String input) {
    final raw = input.trim();
    if (raw.isEmpty) {
      return _Run(
        ScanResult.invalid(
          kind: ScanKind.url,
          issueCode: 'empty',
          detail: 'النص فاضي. اكتب أو الصق رابطًا.',
        ),
        null,
      );
    }
    try {
      return _analyze(raw);
    } catch (_) {
      // أي خطأ غير متوقع = تحليل فاشل (حالة مستقلة)، وده مش معناه "آمن" ولا "مشبوه".
      return _Run(
        ScanResult.failed(
          kind: ScanKind.url,
          detail:
              'حصل خطأ غير متوقع أثناء الفحص، فما نقدرش نحكم عليه. اعتبره غير مفحوص وتعامل بحذر.',
          title: raw,
        ),
        null,
      );
    }
  }

  /// [depth] = 0 للرابط الأصلي، و1 للوجهة المخبّأة جواه (بنحللها مرة واحدة بس،
  /// ومفيش تحليل متداخل أعمق من كده).
  static _Run _analyze(String raw, {int depth = 0}) {
    final n = UrlNormalizer.normalize(raw);
    final f = <Finding>[];

    // 1) أنواع روابط خطيرة (حتى لو مموّهة بحروف خفية أو ترميز)
    if (n.dangerousScheme.isNotEmpty) {
      f.add(const Finding(
        code: 'danger_scheme',
        severity: Severity.danger,
        title: 'نوع رابط خطير',
        detail:
            'هذا ليس عنوان موقع عادي (javascript / data / file ...). قد ينفّذ كودًا أو يفتح ملفًا محليًا.',
        points: 70,
      ));
      return _Run(_finish(f, null, raw, partial: n.truncated), n);
    }

    // 1-ب) التحقق من صحة المدخل قبل أي تحليل: "not-a-url" و "https://" وبروتوكول غير
    // مدعوم = إدخال غير صالح (مالوش درجة خطر)، مش رابط مشبوه ولا رابط نضيف.
    final v = UrlValidator.check(raw, n);
    if (!v.ok) {
      return _Run(
        ScanResult.invalid(
          kind: ScanKind.url,
          issueCode: v.code,
          detail: v.detail,
          title: raw,
        ),
        n,
      );
    }

    // 2) كاشفات التمويه: حروف خفية، ترميز، بروتوكول مكسور، IP، @، homograph ...
    f.addAll(UrlEvasion.detect(n));
    if (!n.valid) {
      return _Run(_finish(f, null, raw, partial: n.truncated), n);
    }

    final scheme = n.scheme;
    final host = n.host;
    // المضيف بعد تحويل الحروف المتشابهة للاتينية (للمقارنة مع أسماء العلامات فقط)
    final brandHost = n.skeletonHost.isEmpty ? host : n.skeletonHost;
    final labels = host.split('.');
    final tld = labels.last;
    final isIp = n.hasIp;

    // الدومين المسجّل واللاحقة العامة من Public Suffix List (المضيف الكامل شيء مختلف).
    var registrable = '';
    var publicSuffix = '';
    var pslListed = true;
    if (!isIp) {
      final m = PublicSuffixList.instance
          .lookup(n.unicodeHost.isEmpty ? host : n.unicodeHost);
      if (m != null && m.labels.length == labels.length) {
        publicSuffix =
            labels.sublist(labels.length - m.suffixLength).join('.');
        if (m.hasRegistrable) {
          registrable =
              labels.sublist(labels.length - m.suffixLength - 1).join('.');
        }
        pslListed = m.listed;
      }
    }
    // لو المضيف نفسه لاحقة عامة (github.io) بنعتبره هو الدومين للمقارنات.
    final domain = isIp ? host : (registrable.isEmpty ? host : registrable);

    final Brand? exact = isIp ? null : _officialOf(host);
    final Brand? regionalBrand =
        (isIp || exact != null) ? null : _regionalOf(domain, tld);
    final Brand? official = exact ?? regionalBrand;
    final bool isRegional = regionalBrand != null;
    var freeHost = false;
    for (final d in kFreeHosts) {
      if (host == d || host.endsWith('.$d')) {
        freeHost = true;
        break;
      }
    }

    // 3) البروتوكول
    if (scheme == 'http') {
      f.add(const Finding(
        code: 'http_plain',
        severity: Severity.info,
        family: kFamilyWeak,
        title: 'اتصال غير مشفّر (HTTP)',
        detail:
            'البيانات المرسلة لهذا الموقع تُنقل بدون تشفير. هذا ليس دليل تصيّد بحد ذاته (مواقع قديمة وداخلية كثيرة تستخدمه، ومواقع التصيّد نفسها غالبًا HTTPS)، لكن لا تُدخل بيانات حساسة.',
        points: 3,
      ));
    }

    // امتداد غير موجود في قائمة اللاحقات المضمّنة (معلومة فقط، مش دليل: قد يكون جديدًا).
    if (!isIp && !pslListed && !n.schemeAssumed) {
      f.add(Finding(
        code: 'unknown_tld',
        severity: Severity.info,
        family: kFamilyWeak,
        title: 'امتداد غير معروف (.$tld)',
        detail:
            'الامتداد غير موجود في قائمة اللاحقات العامة المضمّنة (تاريخها $kPslSnapshotDate). قد يكون امتدادًا جديدًا، أو غير حقيقي.',
      ));
    }

    // 6) منطق الدومين (لا ينطبق على IP)
    if (!isIp) {
      final isShortener =
          kShorteners.contains(host) || kShorteners.contains(domain);
      if (isShortener) {
        f.add(const Finding(
          code: 'shortener',
          severity: Severity.warn,
          title: 'رابط مختصر',
          detail:
              'الرابط المختصر يخفي الوجهة الحقيقية. استخدم زر "فحص الوجهة الفعلية" لمعرفة أين يذهب.',
          points: 20,
        ));
      }

      if (freeHost) {
        f.add(const Finding(
          code: 'free_host',
          severity: Severity.warn,
          title: 'منصة محتوى مفتوحة للمستخدمين',
          detail:
              'المحتالون يرفعون صفحات أو يفتحون حسابات وقنوات مزيفة على منصات مفتوحة (استضافة مجانية، تخزين، تيليجرام...). الدومين نفسه موثوق لكن المحتوى قد لا يكون.',
          points: 15,
        ));
      }

      if (official == null) {
        // انتحال اسم علامة معروفة
        // لو الدومين اتعلّم كنسخة مموّهة من دومين رسمي، ما نعدّش الانتحال مرتين.
        final lookalikeDone = f.any((x) => x.code == 'official_lookalike');
        final tokens = lookalikeDone
            ? <String>[]
            : brandHost
                .split(RegExp(r'[.\-_]'))
                .where((t) => t.length >= 3)
                .toList();
        final hayHost = '$brandHost ${n.path} ${n.query}'.toLowerCase();
        final sensitive = kUrlWords.any((w) => hayHost.contains(w)) ||
            kRiskyTlds.contains(tld);
        Brand? hit;
        outer:
        for (final b in kBrands) {
          for (final key in b.keys) {
            for (final t in tokens) {
              if (t == key || (key.length >= 5 && t.startsWith(key))) {
                // أسماء مثل apple/orange كلمات عادية: لا نحكم إلا مع علامات أخرى
                if (b.ambiguous && !sensitive) continue;
                hit = b;
                break outer;
              }
            }
          }
        }
        if (hit != null) {
          f.add(Finding(
            code: 'brand_impersonation',
            severity: Severity.danger,
            title: 'ينتحل اسم ${hit.name}',
            detail:
                'الاسم موجود في الرابط لكن الدومين الحقيقي هنا هو "$domain"، وهو ليس ضمن الدومينات الرسمية المعروفة لـ ${hit.name} (مثل ${hit.domains.first}).',
            points: 40,
          ));
        } else {
          // تقليد بحروف/أرقام متشابهة
          var found = false;
          for (final t in tokens) {
            if (t.length < 4 || found) continue;
            final variants = _deob(t);
            for (final b in kBrands) {
              for (final key in b.keys) {
                if (key.length < 5 || found) continue;
                if (t != key && variants.contains(key)) {
                  f.add(Finding(
                    code: 'brand_lookalike',
                    severity: Severity.danger,
                    title: 'تقليد لاسم ${b.name}',
                    detail:
                        '"$t" يشبه "$key" باستبدال أرقام/حروف متشابهة (مثل 1 بدل l).',
                    points: 40,
                  ));
                  found = true;
                  break;
                }
                if (!b.ambiguous &&
                    (t.length - key.length).abs() <= 1 &&
                    _lev(t, key) == 1) {
                  f.add(Finding(
                    code: 'brand_typo',
                    severity: Severity.danger,
                    title: 'خطأ إملائي مقصود في ${b.name}؟',
                    detail: '"$t" قريب جدًا من "$key" بحرف واحد مختلف.',
                    points: 30,
                  ));
                  found = true;
                  break;
                }
              }
            }
          }
        }

        if (kRiskyTlds.contains(tld)) {
          f.add(Finding(
            code: 'risky_tld',
            severity: Severity.info,
            family: kFamilyWeak,
            title: 'امتداد دومين كثير الاستخدام في الاحتيال (.$tld)',
            detail:
                'الامتداد رخيص أو مجاني فيتكرر في الحملات الاحتيالية، لكن مواقع سليمة كثيرة تستخدمه أيضًا. إشارة مساعدة فقط وليست دليلًا وحدها.',
            points: 5,
          ));
        }

        final extra = labels.length - domain.split('.').length;
        if (extra >= 3) {
          f.add(Finding(
            code: 'many_subdomains',
            severity: Severity.warn,
            title: 'مستويات فرعية كثيرة ($extra)',
            detail: 'كثرة النقاط في الدومين تُستخدم لدفن الاسم الحقيقي في آخر الرابط.',
            points: UrlWeights.manySubdomains,
          ));
        } else if (extra == 2) {
          f.add(Finding(
            code: 'multi_subdomain',
            severity: Severity.info,
            family: kFamilyWeak,
            title: 'دومين فرعي متعدد',
            detail:
                'الدومين الحقيقي هو آخر جزأين قبل أول "/" (هنا "$domain")، وكل ما قبله مجرد تسميات فرعية يضعها صاحب الموقع كما يشاء.',
            points: 3,
          ));
        }

        if ('-'.allMatches(host.replaceAll('xn--', '')).length >= 3) {
          f.add(const Finding(
            code: 'many_hyphens',
            severity: Severity.info,
            family: kFamilyWeak,
            title: 'شرطات كثيرة في الدومين',
            detail:
                'الدومينات الاحتيالية غالبًا تحشر كلمات مثل secure-login-update، لكن أسماء سليمة طويلة تحتوي شرطات أيضًا. إشارة مساعدة فقط.',
            points: 3,
          ));
        }
        if (host.length > 35) {
          f.add(const Finding(
            code: 'long_host',
            severity: Severity.info,
            family: kFamilyWeak,
            title: 'اسم دومين طويل',
            detail: 'الأسماء الطويلة قد تُستخدم لإخفاء الجزء المهم، لكنها وحدها ليست دليلًا.',
            points: 2,
          ));
        }
      } else if (!freeHost && !isShortener) {
        // (الرابط المختصر لعلامة كبيرة t.co / lnkd.in مش بنقول عليه "دومين رسمي" وهو مختصر)
        if (isRegional) {
          f.add(Finding(
            code: 'regional_brand',
            severity: Severity.info,
            title: 'نطاق إقليمي محتمل لـ ${official.name}',
            detail:
                '"$domain" يبدو نطاقًا إقليميًا لـ ${official.name}. غالبًا سليم، لكن تأكد من الكتابة الصحيحة.',
          ));
        } else {
          f.add(Finding(
            code: 'official_domain',
            severity: Severity.good,
            title: 'الدومين رسمي: ${official.name}',
            detail: '"$domain" ضمن الدومينات الرسمية المعروفة لـ ${official.name}.',
          ));
        }
      }
    }

    // 7) المنفذ
    final port = n.port;
    if (port != null && port != 80 && port != 443) {
      f.add(Finding(
        code: 'odd_port',
        severity: Severity.warn,
        title: 'منفذ غير معتاد ($port)',
        detail: 'المواقع العادية لا تحتاج رقم منفذ ظاهرًا في الرابط.',
        points: 10,
      ));
    }

    // 8) كلمات حساسة في الرابط: مش دليل وحدها (login / account / pay موجودة في مواقع
    // سليمة كتير). بنطابق الكلمة كاملة (مش جزء من كلمة)، وبتاخد نقاط بس في سياق:
    // كلمات كتير فيها كلمة دخول/تحقق، أو مع مؤشر قوي تاني (راجع keywords_in_context).
    var credHits = <String>[];
    var allHits = <String>[];
    if (official == null || freeHost) {
      final hay = '$brandHost ${n.path} ${n.query}'.toLowerCase();
      final tokens = hay
          .split(RegExp(r'[^a-z0-9]+'))
          .where((t) => t.isNotEmpty)
          .toList();
      final hits = kUrlWords.where((w) => _wordHit(hay, tokens, w)).toList();
      // كلمات عربية في المسار/الاستعلام (النص هنا متفكوك الترميز، فبتتطابق حتى لو كانت %D8..)
      final ar = _arabicHits('${n.path} ${n.query}');
      credHits = <String>[...hits.where(_credWords.contains), ...ar.cred];
      allHits = <String>[...hits, ...ar.cred, ...ar.general];
      if (allHits.length >= 3 && credHits.isNotEmpty) {
        f.add(Finding(
          code: 'keyword_stuffing',
          severity: Severity.warn,
          title: 'كلمات حساسة كثيرة',
          detail:
              'وُجدت: ${allHits.take(5).join('، ')}. صفحات الاحتيال تحشر هذه الكلمات لإقناعك.',
          points: UrlWeights.keywordStuffing,
        ));
      } else if (allHits.isNotEmpty) {
        f.add(Finding(
          code: 'keywords',
          severity: Severity.info,
          family: kFamilyWeak,
          title: 'كلمات حساسة في الرابط (لا تكفي وحدها)',
          detail:
              'وُجدت: ${allHits.join('، ')}. هذه كلمات عادية في مواقع كثيرة، فلا نعتبرها مؤشر خطر إلا إذا اجتمعت مع مؤشرات أخرى.',
        ));
      }
    }

    // 8-ب) اسم علامة معروفة في المسار (evil.com/paypal/login) أو دومين يبدو عشوائيًا
    if (!isIp && (official == null || freeHost)) {
      final pathHay = '${n.path} ${n.query}'.toLowerCase();
      final allHay = '$host $pathHay';
      // كلمات "تسجيل الدخول/التحقق" فقط (مش pay/account/bank لأنها شائعة في الأخبار)
      final sensitiveCtx =
          _credWords.any((w) => allHay.contains(w)) || kRiskyTlds.contains(tld);
      final alreadyBrand = f.any(
          (x) => x.title.startsWith('ينتحل') || x.title.startsWith('تقليد'));
      if (sensitiveCtx && !alreadyBrand) {
        Brand? inPath;
        for (final b in kBrands) {
          if (b.ambiguous || identical(b, official)) continue;
          for (final key in b.keys) {
            if (key.length >= 5 && pathHay.contains(key)) {
              inPath = b;
              break;
            }
          }
          if (inPath != null) break;
        }
        if (inPath != null) {
          f.add(Finding(
            code: 'brand_in_path',
            severity: Severity.warn,
            title: 'اسم ${inPath.name} داخل مسار الرابط',
            detail:
                'الدومين الحقيقي هنا "$domain" وليس ${inPath.domains.first}. المحتال يضع اسم العلامة بعد الدومين ليبدو الرابط مألوفًا.',
            points: 18,
          ));
        }
      }
      if (official == null && !freeHost && _looksRandom(domain.split('.').first)) {
        f.add(const Finding(
          code: 'random_domain',
          severity: Severity.warn,
          title: 'اسم دومين يبدو عشوائيًا',
          detail:
              'الاسم يشبه نصًا مولَّدًا آليًا لا كلمة مفهومة. الدومينات المؤقتة للحملات الاحتيالية غالبًا بهذا الشكل.',
          points: 15,
        ));
      }
    }

    // 9) إعادة توجيه داخل الرابط
    // الاستعلام هنا متفكوك الترميز بالكامل (حتى المزدوج)، فنكشف الوجهة المخبّأة.
    // بنحلل الوجهة المخبّأة بنفس المحرك (مرة واحدة)، مش بس نلاحظ وجودها: لو وجهتها IP
    // أو دومين منتحل، ده بيظهر في الدرجة. وبنفك الوجهة لو كانت base64 أو من غير http.
    final redirect = _findRedirectTarget(n.query);
    if (redirect != null || _embedded.allMatches(raw).length >= 2) {
      ScanResult? sub;
      if (redirect != null && depth == 0) sub = _analyzeTarget(redirect.url);
      final subParts = sub?.parts;
      final subHost = subParts?.host ?? '';
      final subDomain = subParts?.domain ?? '';
      // نفس الموقع (مثلًا accounts.google.com?continue=https://mail.google.com) = تنقّل عادي.
      final sameSite = subDomain.isNotEmpty && subDomain == domain;
      final bothOfficial = subHost.isNotEmpty &&
          official != null &&
          !freeHost &&
          officialBrandOf(subHost) != null;
      if (!sameSite && !bothOfficial) {
        f.add(Finding(
          code: 'nested_url',
          severity: Severity.warn,
          title: 'رابط داخل رابط',
          detail: subHost.isEmpty
              ? 'الرابط يحمل عنوانًا آخر بداخله وقد يحوّلك لموقع مختلف تمامًا.'
              : 'الرابط يحمل عنوانًا آخر بداخله ("$subHost") وقد يحوّلك لموقع مختلف تمامًا.',
          points: 15,
        ));
        if (redirect != null && redirect.encoded) {
          f.add(const Finding(
            code: 'nested_url_encoded',
            severity: Severity.warn,
            title: 'الوجهة مخبّأة بترميز base64',
            detail:
                'الوجهة الحقيقية مكتوبة بترميز base64 فلا تظهر للعين. فككناها وفحصناها. المواقع العادية نادرًا ما تخبّئ وجهة التحويل بهذا الشكل.',
            points: 10,
          ));
        }
        if (sub != null && sub.hasScore && sub.score >= kBandMedium) {
          final why = sub.findings
              .where((x) => x.points > 0)
              .take(3)
              .map((x) => x.title)
              .join('، ');
          f.add(Finding(
            code: 'nested_target_risk',
            severity: Severity.danger,
            title: 'الوجهة المخبّأة داخل الرابط مشبوهة',
            detail:
                'الرابط يحمل وجهة ثانية "$subHost" فحصناها بنفس المحرك فطلعت بدرجة ${sub.score}/100${why.isEmpty ? '' : ' ($why)'}.',
            points: math.min(35, (sub.score * 0.6).round()),
          ));
        }
      }
    }

    // 10) أطوال وترميز
    if (raw.length > 200) {
      f.add(const Finding(
        code: 'very_long',
        severity: Severity.info,
        family: kFamilyWeak,
        title: 'رابط طويل جدًا',
        detail: 'الطول الزائد قد يُستخدم لإخفاء الجزء المهم، لكنه شائع في روابط التتبع السليمة.',
        points: 4,
      ));
    } else if (raw.length > 100) {
      f.add(const Finding(
        code: 'long_url',
        severity: Severity.info,
        family: kFamilyWeak,
        title: 'رابط طويل',
        detail: 'الروابط الطويلة تستحق نظرة أدق.',
        points: 2,
      ));
    }
    if ('%'.allMatches(raw).length >= 6) {
      f.add(const Finding(
        code: 'heavy_encoding',
        severity: Severity.info,
        family: kFamilyWeak,
        title: 'ترميز كثيف (%)',
        detail: 'الترميز الكثيف قد يُستخدم لتمويه محتوى الرابط (وفي روابط عربية سليمة كثيرة أيضًا).',
        points: 3,
      ));
    }

    // 11) ملفات خطيرة
    final path = n.path.toLowerCase();
    var dangerous = false;
    for (final ext in kDangerExt) {
      if (path.endsWith(ext)) {
        dangerous = true;
        f.add(Finding(
          code: 'executable_download',
          severity: Severity.danger,
          title: 'تحميل ملف تنفيذي ($ext)',
          detail:
              'ملفات $ext قد تثبّت برامج ضارة. لا تثبّت شيئًا إلا من المتجر الرسمي أو موقع الناشر.',
          points: 30,
        ));
        break;
      }
    }
    if (!dangerous) {
      for (final ext in kArchiveExt) {
        if (path.endsWith(ext)) {
          f.add(Finding(
            code: 'archive_download',
            severity: Severity.warn,
            title: 'ملف مضغوط ($ext)',
            detail: 'الملفات المضغوطة تُستخدم لإخفاء برامج ضارة عن الفلاتر.',
            points: 12,
          ));
          break;
        }
      }
    }

    // كلمات دخول/تحقق + مؤشر قوي تاني (انتحال علامة، IP، @، دومين عشوائي، امتداد
    // مشبوه، رابط مختصر...) = سياق احتيال. الكلمات لوحدها ما بتتحسبش.
    // لو "كلمات حساسة كثيرة" اتحسبت خلاص، ما نحسبش نفس الكلمات تاني كسياق (عدّ مزدوج).
    // ولو السياق اتحسب، سطر "لا تكفي وحدها" بيتشال عشان ما يتناقضش معاه.
    final stuffingDone = f.any((x) => x.code == 'keyword_stuffing');
    if (credHits.isNotEmpty &&
        !stuffingDone &&
        f.any((x) => _contextCodes.contains(x.code))) {
      f.removeWhere((x) => x.code == 'keywords');
      f.add(Finding(
        code: 'keywords_in_context',
        severity: Severity.warn,
        title: 'كلمات دخول/تحقق مع مؤشرات أخرى',
        detail:
            'وُجدت: ${credHits.join('، ')}، وتتزامن مع مؤشرات أخرى في الرابط. اجتماع الاثنين هو الذي يرفع الشك، وليست الكلمات وحدها.',
        points: 6,
      ));
    }

    // حدود دنيا لتجمعات إشارات نادرة جدًا في المواقع السليمة (راجع _applyComboFloor).
    _applyComboFloor(
      f,
      n,
      credHits: credHits,
      allHits: allHits,
      extraLabels: isIp ? 0 : labels.length - domain.split('.').length,
      riskyTld: !isIp && kRiskyTlds.contains(tld),
    );

    if (!f.any((x) => x.points > 0 || x.severity == Severity.good)) {
      f.add(const Finding(
        code: 'no_indicators',
        severity: Severity.good,
        title: 'لا علامات تصيّد شائعة',
        detail:
            'لم يطابق الرابط أي قاعدة فحص. هذا لا يضمن أنه آمن، فقد يكون دومينًا جديدًا مخترقًا.',
      ));
    }

    final parts = UrlParts(
      scheme: scheme,
      host: host,
      domain: domain,
      tld: tld,
      path: n.path.isEmpty ? '/' : n.path,
      query: n.query,
      port: port == null ? '' : '$port',
      // نسخة صالحة للاتصال (الهيكل الخام سليم، المضيف بشكله القياسي)
      normalizedUrl: n.fetchUrl,
      registrableDomain: registrable,
      publicSuffix: publicSuffix,
      unicodeHost: n.unicodeHost,
      asciiHost: _asciiHost(host),
      pslListed: pslListed,
    );
    // العنوان = اسم المضيف الكامل (مش الدومين المسجّل فقط).
    return _Run(_finish(f, parts, host, partial: n.truncated), n);
  }

  /// إشارات تعتبر "سياق" لكلمات الدخول/التحقق (راجع keywords_in_context).
  static const Set<String> _contextCodes = <String>{
    'brand_impersonation',
    'brand_lookalike',
    'brand_typo',
    'official_lookalike',
    'homograph',
    'brand_in_path',
    'ip_host',
    'ip_obfuscated',
    'userinfo_at',
    'random_domain',
    'shortener',
    'free_host',
    'nested_url',
    'risky_tld',
  };

  static final RegExp _httpStart = RegExp(r'^https?://', caseSensitive: false);
  static final RegExp _b64Chars = RegExp(r'^[A-Za-z0-9_\-+/]+={0,2}$');
  static final RegExp _bareDomain = RegExp(
    r'^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+([a-z]{2,24})(?::\d{1,5})?(?:[/?#].*)?$',
    caseSensitive: false,
  );
  static final RegExp _domainInUserInfo =
      RegExp(r'(?:[a-z0-9\-]+\.)+([a-z]{2,24})', caseSensitive: false);
  static final RegExp _nonArabicWord = RegExp(r'[^a-z0-9ء-ي]+');
  static final List<MapEntry<String, RegExp>> _arCredRe =
      <MapEntry<String, RegExp>>[
    for (final w in kCredWordsAr) MapEntry<String, RegExp>(w, buildKeywordRegex(w)),
  ];
  static final List<MapEntry<String, RegExp>> _arGeneralRe =
      <MapEntry<String, RegExp>>[
    for (final w in kUrlWordsAr) MapEntry<String, RegExp>(w, buildKeywordRegex(w)),
  ];

  /// كلمات عربية (دخول/تحقق وكلمات مالية/مخالفات) في النص. بنطابق على نص موحّد
  /// والفواصل (- _ / + مسافة) بتتحول لمسافة، فـ "تسجيل-الدخول" تطابق "تسجيل الدخول".
  static _ArHits _arabicHits(String text) {
    var hasArabic = false;
    for (final r in text.runes) {
      if (r >= 0x0600 && r <= 0x06FF) {
        hasArabic = true;
        break;
      }
    }
    if (!hasArabic) return const _ArHits(<String>[], <String>[]);
    final norm = normalizeText(text).replaceAll(_nonArabicWord, ' ');
    final cred = <String>[];
    for (final e in _arCredRe) {
      if (e.value.hasMatch(norm)) cred.add(e.key);
    }
    final general = <String>[];
    for (final e in _arGeneralRe) {
      if (e.value.hasMatch(norm)) general.add(e.key);
    }
    return _ArHits(cred, general);
  }

  /// الوجهة المخبّأة في باراميتر إعادة توجيه: رابط صريح (http:// أو //)، أو (للباراميترات
  /// الصريحة بس) قيمة base64 بتتفك لرابط، أو اسم دومين من غير http (?redirect=evil.com).
  static _RedirectTarget? _findRedirectTarget(String query) {
    for (final pair in _queryPairs(query)) {
      final key = pair[0].toLowerCase();
      if (!kRedirectParams.contains(key)) continue;
      final v = pair[1].trim();
      if (v.isEmpty) continue;
      if (_redirectValue.hasMatch(v)) {
        return _RedirectTarget(v.startsWith('//') ? 'https:$v' : v, false);
      }
      if (!kStrictRedirectParams.contains(key)) continue;
      final decoded = _decodeBase64Url(v);
      if (decoded != null) return _RedirectTarget(decoded, true);
      final bare = _bareDomainUrl(v);
      if (bare != null) return _RedirectTarget(bare, false);
    }
    return null;
  }

  /// يفك قيمة base64 / base64url لو ناتجها نص UTF-8 صالح بيبدأ بـ http(s)://. غير كده null
  /// (توكنات الجلسات والصور ما بتتفكش لرابط، فمفيش إنذار كاذب).
  static String? _decodeBase64Url(String v) {
    if (v.length < 12 || v.length > 2048 || !_b64Chars.hasMatch(v)) return null;
    try {
      var s = v.replaceAll('-', '+').replaceAll('_', '/');
      while (s.length % 4 != 0) {
        s += '=';
      }
      final text = utf8.decode(base64.decode(s)).trim();
      return _httpStart.hasMatch(text) ? text : null;
    } catch (_) {
      return null;
    }
  }

  /// "evil.com/x" -> "https://evil.com/x" لو الامتداد فعلًا TLD معروف (file.txt لا).
  static String? _bareDomainUrl(String v) {
    final m = _bareDomain.firstMatch(v);
    if (m == null) return null;
    if (!PublicSuffixList.instance.isKnownTld(m.group(1)!.toLowerCase())) {
      return null;
    }
    return 'https://$v';
  }

  /// يحلل الوجهة المخبّأة بنفس المحرك (عمق 1)، أو null لو مش قابلة للتحليل.
  static ScanResult? _analyzeTarget(String url) {
    try {
      final r = _analyze(url, depth: 1).result;
      return r.hasScore ? r : null;
    } catch (_) {
      return null;
    }
  }

  /// الجزء قبل @ مكتوب كاسم موقع (paypal.com / www.google.com:443): المتصفح بيتجاهله.
  static bool _userInfoLooksLikeDomain(String userInfo) {
    for (final m in _domainInUserInfo.allMatches(userInfo.toLowerCase())) {
      if (PublicSuffixList.instance.isKnownTld(m.group(1)!)) return true;
    }
    return false;
  }

  /// حدود دنيا لتجمعات إشارات معروفة بأنها نادرة جدًا في المواقع السليمة. الجمع الحسابي
  /// لوحده بيخلّي روابط تصيّد واضحة (علامة معروفة + login على دومين تاني) تطلع أقل من اللازم.
  /// لو الحد أعلى من الدرجة الحالية، بنضيف إشارة 'combo_floor' بالفرق عشان مجموع النقاط
  /// المعروضة يفضل مطابق للدرجة وسبب الرفع يبان للمستخدم.
  static void _applyComboFloor(
    List<Finding> f,
    NormalizedUrl n, {
    required List<String> credHits,
    required List<String> allHits,
    required int extraLabels,
    required bool riskyTld,
  }) {
    bool has(String c) => f.any((x) => x.code == c);
    var floor = 0;
    var why = '';
    void raise(int v, String reason) {
      if (v > floor) {
        floor = v;
        why = reason;
      }
    }

    final brand = has('brand_impersonation') ||
        has('brand_lookalike') ||
        has('official_lookalike');
    final sensitive = allHits.isNotEmpty || riskyTld || extraLabels >= 2;

    if (has('userinfo_at') && _userInfoLooksLikeDomain(n.userInfo)) {
      raise(UrlWeights.floorUserInfoDomain,
          'الجزء قبل @ مكتوب كأنه اسم موقع آخر. المتصفح يتجاهله ويذهب لما بعد @، وهذا الشكل لا يستخدمه موقع سليم تقريبًا.');
    }
    if (brand && has('homograph')) {
      raise(UrlWeights.floorBrandHomograph,
          'اسم علامة معروفة مكتوب بحروف متشابهة من أنظمة كتابة مختلفة.');
    }
    if (brand && sensitive) {
      raise(UrlWeights.floorBrandContext,
          'اسم علامة معروفة داخل دومين ليس لها، مع كلمات حساسة أو مؤشرات أخرى. هذا هو الشكل الكلاسيكي للتصيّد.');
    }
    if (has('brand_typo') && credHits.isNotEmpty) {
      raise(UrlWeights.floorBrandTypo,
          'خطأ إملائي مقصود في اسم علامة معروفة مع كلمات دخول/تحقق.');
    }
    if (has('ip_obfuscated')) {
      raise(
        allHits.isNotEmpty
            ? UrlWeights.floorObfuscatedIpWords
            : UrlWeights.floorObfuscatedIp,
        'كتابة عنوان IP بصيغة مموّهة (رقم واحد أو hex أو ثُماني) ليس لها استخدام سليم تقريبًا.',
      );
    }
    if (has('ip_host') && !has('ip_internal') && allHits.isNotEmpty) {
      raise(UrlWeights.floorPublicIpWords,
          'عنوان IP عام مباشر مع كلمات حساسة (دخول/دفع/تحقق...) بدل اسم موقع.');
    }
    if (has('host_encoded') && credHits.isNotEmpty) {
      raise(UrlWeights.floorEncodedHostWords,
          'اسم الدومين نفسه مكتوب بترميز %XX مع كلمات دخول/تحقق.');
    }

    if (floor == 0) return;
    final total = aggregateScore(f);
    if (floor > total) {
      f.add(Finding(
        code: 'combo_floor',
        severity: Severity.danger,
        title: 'اجتماع علامات خطر نادر في المواقع السليمة',
        detail: why,
        points: floor - total,
      ));
    }
  }

  /// مطابقة كلمة كاملة (مش جزء من كلمة): pay لا تطابق paypal، وupdate تطابق updates.
  static bool _wordHit(String hay, List<String> tokens, String w) {
    if (w.contains('-')) return hay.contains(w);
    for (final t in tokens) {
      if (t == w || t == '${w}s') return true;
      if (w.length >= 6 && t.startsWith(w)) return true;
    }
    return false;
  }

  /// المضيف بصيغة ASCII للعرض: لو فيه حروف دولية بنحوّل كل ليبل لـ xn--.
  static String _asciiHost(String host) {
    if (!host.runes.any((r) => r >= 0x80)) return host;
    final out = <String>[];
    for (final l in host.split('.')) {
      if (l.runes.any((r) => r >= 0x80)) {
        final e = UrlNormalizer.encodePunycode(l);
        out.add(e == null ? l : 'xn--$e');
      } else {
        out.add(l);
      }
    }
    return out.join('.');
  }

  /// أزواج (اسم، قيمة) من نص الاستعلام. بدون استثناءات حتى لو النص مكسور.
  static List<List<String>> _queryPairs(String q) {
    final out = <List<String>>[];
    if (q.isEmpty) return out;
    for (final part in q.split('&')) {
      final i = part.indexOf('=');
      if (i <= 0) continue;
      out.add(<String>[part.substring(0, i), part.substring(i + 1)]);
    }
    return out;
  }
}
