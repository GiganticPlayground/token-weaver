import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { checkPathAccess, validatePathPatterns } from '../../src/auth/index';

/**
 * Method-pinned patterns and the leading-slash normalization that keeps them from silently
 * failing to match. A pattern that cannot match is worst in a blacklist: the rule reads as
 * configured while the path stays reachable, so these cases are about removing that trap.
 */
void describe('checkPathAccess — leading slash normalization', () => {
  void it('treats a leading slash as optional on the pattern', () => {
    for (const pattern of ['orders/list', '/orders/list']) {
      assert.equal(checkPathAccess('orders/list', { whitelist: [pattern] }), true, pattern);
      assert.equal(checkPathAccess('/orders/list', { whitelist: [pattern] }), true, pattern);
    }
  });

  void it('treats a leading slash as optional on a method-pinned pattern', () => {
    // The trap this fixes: 'post /orders/create' used to normalize only at the very start of
    // the string, so the slash after the method prefix made the rule unmatchable.
    for (const pattern of ['post orders/create', 'post /orders/create']) {
      assert.equal(checkPathAccess('post orders/create', { blacklist: [pattern] }), false, pattern);
      assert.equal(
        checkPathAccess('post /orders/create', { blacklist: [pattern] }),
        false,
        pattern,
      );
    }
  });

  void it('keeps the method prefix significant after normalization', () => {
    const paths = { whitelist: ['get /orders/*'] };
    assert.equal(checkPathAccess('get orders/list', paths), true);
    assert.equal(checkPathAccess('post orders/list', paths), false);
  });

  void it('matches the method prefix case-insensitively', () => {
    assert.equal(checkPathAccess('post orders/create', { blacklist: ['POST orders/create'] }), false);
    assert.equal(checkPathAccess('POST orders/create', { blacklist: ['post orders/create'] }), false);
  });

  void it('leaves a non-method first token as part of the path', () => {
    // 'pos' is not a method, so the whole string stays a literal path and does not become a
    // method prefix matching anything.
    assert.equal(checkPathAccess('pos orders/create', { whitelist: ['pos orders/create'] }), true);
    assert.equal(checkPathAccess('post orders/create', { whitelist: ['pos orders/create'] }), false);
  });
});

void describe('validatePathPatterns', () => {
  void it('accepts bare, slashed, wildcard and method-pinned patterns', () => {
    assert.deepEqual(
      validatePathPatterns([
        'orders/list',
        '/orders/list',
        'orders/*',
        'get orders/*',
        'GET /orders/*',
        'delete orders/{id}',
      ]),
      [],
    );
  });

  void it('reports a typo’d method prefix', () => {
    const issues = validatePathPatterns(['pos orders/create']);
    assert.equal(issues.length, 1);
    assert.equal(issues[0]?.pattern, 'pos orders/create');
    assert.match(issues[0]?.message ?? '', /not a valid HTTP method prefix/);
    assert.match(issues[0]?.message ?? '', /post/);
  });

  void it('reports an empty pattern', () => {
    const issues = validatePathPatterns(['', '   ']);
    assert.equal(issues.length, 2);
    for (const issue of issues) {
      assert.match(issue.message, /empty/);
    }
  });

  void it('reports a method prefix with no path', () => {
    // 'get ' trims to a bare method, which would only ever match a path literally named 'get'.
    for (const pattern of ['get ', 'get', 'DELETE']) {
      const issues = validatePathPatterns([pattern]);
      assert.equal(issues.length, 1, pattern);
      assert.match(issues[0]?.message ?? '', /no path|not followed by a path/);
    }
  });

  void it('does not flag a leading slash, which the matcher normalizes', () => {
    assert.deepEqual(validatePathPatterns(['/orders/list', 'post /orders/create']), []);
  });

  void it('reports every offending pattern in one pass', () => {
    const issues = validatePathPatterns(['get orders/*', 'nope orders/x', '', 'patch orders/y']);
    assert.equal(issues.length, 2);
    assert.deepEqual(
      issues.map((issue) => issue.pattern),
      ['nope orders/x', ''],
    );
  });
});
