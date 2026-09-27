import test from 'node:test'
import assert from 'node:assert/strict'
import { createReviewQueue, isGeminiResult, requestGeminiReview } from '../lib/gemini-review.ts'

const result = { review: 'Assessment\nObserved imports suggest network access.', model: 'test-model' }

test('reuses an existing review without sending it again', async () => {
    const enqueue = createReviewQueue(async () => { throw new Error('Unexpected request') })
    assert.deepEqual(await enqueue({ gemini_review: result }), result)
    assert.equal(isGeminiResult({ review: '', model: 'test' }), false)
})

test('deduplicates submissions and serializes reviews', async () => {
    let active = 0
    let calls = 0
    const enqueue = createReviewQueue(async () => {
        calls++
        active++
        assert.equal(active, 1)
        await new Promise(resolve => setTimeout(resolve, 5))
        active--
        return result
    })
    const report = {}
    const first = enqueue(report)
    assert.equal(enqueue(report), first)
    await Promise.all([first, enqueue({})])
    assert.equal(calls, 2)
})

test('continues after errors and retries only when requested', async () => {
    let calls = 0
    const enqueue = createReviewQueue(async () => {
        if (++calls === 1) throw new Error('Quota reached')
        return result
    })
    const report = {}
    await assert.rejects(enqueue(report), /Quota reached/)
    await assert.rejects(enqueue(report), /Quota reached/)
    assert.equal(calls, 1)
    assert.deepEqual(await enqueue({}), result)
    assert.deepEqual(await enqueue(report, () => {}, true), result)
    assert.equal(calls, 3)
})

test('sends the complete behavior evidence to the existing review endpoint', async t => {
    const report = { analysis: { file: { file_name: 'sample.exe' }, imports: ['network'] }, risk_assessment: { behaviors: [{ reason: 'Network access' }], risk: { points: 2 } } }
    t.mock.method(globalThis, 'fetch', async (url, options) => {
        assert.equal(url, '/api/review')
        assert.equal(options.method, 'POST')
        assert.deepEqual(JSON.parse(options.body), report)
        assert.ok(options.signal instanceof AbortSignal)
        return Response.json(result)
    })
    assert.deepEqual(await requestGeminiReview(report), result)
})

test('surfaces service errors and rejects malformed results', async t => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json({ detail: 'Gemini is not configured.' }, { status: 503 }))
    await assert.rejects(requestGeminiReview({}), /Gemini is not configured/)
    fetch.mock.mockImplementation(async () => Response.json({ review: ' ', model: 'test' }))
    await assert.rejects(requestGeminiReview({}), /invalid review/)
})
