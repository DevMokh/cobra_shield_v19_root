import 'package:flutter_test/flutter_test.dart';

import 'package:cobra_shield/services/batch_input.dart';

// فحص الدفعة: ما نسقّطش رابط مموّه بصمت. (بج حقيقي في 1.11.0: أي نص فيه @ من غير http كان
// بيتتجاهل، فرابط hxxp:\\www.google.com@0x7f000001/... اختفى من تقرير الدفعة.)
void main() {
  group('BatchInput.parse', () {
    test('روابط عادية مفصولة بمسافات وفواصل (عربية وإنجليزية)', () {
      final p = BatchInput.parse('https://a.com/x, www.b.com ; c.org،d.eg');
      expect(p.links, <String>['https://a.com/x', 'www.b.com', 'c.org', 'd.eg']);
      expect(p.unrecognized, isEmpty);
      expect(p.overflow, 0);
    });

    test('رابط مموّه بـ hxxp:\\\\ و@ وhex: لازم يتفحص (البج اللي اتصلّح)', () {
      final p = BatchInput.parse('hxxp:\\\\www.google.com@0x7f000001/login');
      expect(p.links, <String>['hxxp:\\\\www.google.com@0x7f000001/login']);
    });

    test('اسم موقع قبل @ (paypal.com@evil.com) = رابط مش إيميل', () {
      expect(BatchInput.parse('paypal.com@evil.com').links, <String>['paypal.com@evil.com']);
      expect(BatchInput.isEmail('paypal.com@evil.com'), isFalse);
    });

    test('إيميل حقيقي بيتتجاهل (مش رابط)', () {
      for (final e in <String>['ahmed@gmail.com', 'john.smith@example.com', 'a_b-c@mail.example.org']) {
        final p = BatchInput.parse(e);
        expect(p.links, isEmpty, reason: e);
        expect(p.unrecognized, isEmpty, reason: e);
      }
    });

    test('مضيف رقمي (hex أو عشري كبير) بمسار', () {
      expect(BatchInput.parse('0x7f000001/login').links, <String>['0x7f000001/login']);
      expect(BatchInput.parse('3232235777/x').links, <String>['3232235777/x']);
    });

    test('أرقام عادية (تليفون) مش روابط', () {
      final p = BatchInput.parse('01012345678 12345');
      expect(p.links, isEmpty);
      expect(p.unrecognized, isEmpty);
    });

    test('نص فيه / أو \\ ومش متعرف عليه كرابط: بيظهر "غير مفحوص" بدل ما يختفي', () {
      final p = BatchInput.parse('foo/bar C:\\\\Windows\\\\x hello');
      expect(p.links, isEmpty);
      expect(p.unrecognized, <String>['foo/bar', 'C:\\\\Windows\\\\x']);
    });

    test('علامات ترقيم حوالين الرابط بتتشال', () {
      final p = BatchInput.parse('(https://a.com/x). "www.b.com",');
      expect(p.links, <String>['https://a.com/x', 'www.b.com']);
    });

    test('تكرار (بصرف النظر عن حالة الحروف) بيتدمج', () {
      final p = BatchInput.parse('a.com A.COM a.com');
      expect(p.links.length, 1);
    });

    test('الحد الأقصى: الزيادة بتتعدّ وما بتتفحصش بصمت', () {
      final text = List<String>.generate(35, (i) => 'https://site$i.example.com/').join('\n');
      final p = BatchInput.parse(text);
      expect(p.links.length, BatchInput.defaultMax);
      expect(p.overflow, 5);
      final q = BatchInput.parse(text, max: 10);
      expect(q.links.length, 10);
      expect(q.overflow, 25);
    });
  });
}
