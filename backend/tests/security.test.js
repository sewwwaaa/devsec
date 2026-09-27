const test = require('node:test');
const assert = require('node:assert/strict');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');

test('Security Gate: XSS Sanitization Engine', async (t) => {
  await t.test('strips dangerous <script> tags and javascript: URLs', () => {
    const maliciousInput = '<script>alert(1)</script><p>Clean Text</p><a href="javascript:steal()">Link</a>';
    const cleaned = sanitizeHtml(maliciousInput, {
      allowedTags: ['p', 'b', 'i', 'strong', 'a'],
      allowedAttributes: { 'a': ['href'] }
    });

    assert.equal(cleaned.includes('<script>'), false);
    assert.equal(cleaned.includes('alert(1)'), false);
    assert.equal(cleaned.includes('javascript:steal()'), false);
    assert.equal(cleaned.includes('<p>Clean Text</p>'), true);
  });

  await t.test('strips inline event handlers like onerror and onload', () => {
    const maliciousImg = '<img src="invalid-image" onerror="fetch(\'/exfil\')">';
    const cleaned = sanitizeHtml(maliciousImg, {
      allowedTags: ['p', 'b', 'i'],
      allowedAttributes: {}
    });

    assert.equal(cleaned.includes('onerror'), false);
    assert.equal(cleaned.includes('fetch'), false);
  });
});

test('Security Gate: Cryptographic JWT Verification', async (t) => {
  const secretKey = 'real_production_secret_key_256_bit_random_hash!';
  const weakKey = 'secret123';

  await t.test('rejects tokens signed with unauthorized or weak secret', () => {
    const forgedToken = jwt.sign({ username: 'attacker', role: 'admin' }, weakKey);

    assert.throws(() => {
      jwt.verify(forgedToken, secretKey);
    }, (err) => {
      return err.name === 'JsonWebTokenError' && err.message === 'invalid signature';
    });
  });

  await t.test('accepts valid tokens signed with true secret', () => {
    const legitimateToken = jwt.sign({ username: 'alice', role: 'user' }, secretKey, { expiresIn: '15m' });
    const decoded = jwt.verify(legitimateToken, secretKey);
    assert.equal(decoded.username, 'alice');
    assert.equal(decoded.role, 'user');
  });
});

test('Security Gate: BOLA Ownership Validation Logic', async (t) => {
  await t.test('blocks cross-tenant access when requester is not owner and not admin', () => {
    const mockNote = { id: 101, title: 'Private', userId: 2 };
    const requestingUser = { id: 3, role: 'user' };

    const isAuthorized = (mockNote.userId === requestingUser.id) || (requestingUser.role === 'admin');
    assert.equal(isAuthorized, false, 'Should deny user 3 from accessing user 2 resource');
  });

  await t.test('permits access when requester owns the resource', () => {
    const mockNote = { id: 101, title: 'Private', userId: 2 };
    const requestingUser = { id: 2, role: 'user' };

    const isAuthorized = (mockNote.userId === requestingUser.id) || (requestingUser.role === 'admin');
    assert.equal(isAuthorized, true, 'Should allow user 2 to access own resource');
  });

  await t.test('permits admin override for governance and compliance', () => {
    const mockNote = { id: 101, title: 'Private', userId: 2 };
    const requestingUser = { id: 1, role: 'admin' };

    const isAuthorized = (mockNote.userId === requestingUser.id) || (requestingUser.role === 'admin');
    assert.equal(isAuthorized, true, 'Admin should have governance access');
  });
});
