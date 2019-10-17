
async function post (url, body, fetchMethod = null) {
  const fetch = typeof window !== 'undefined' && window.fetch != null ? window.fetch : await import('node-fetch')
  const data = JSON.stringify(body)
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: headers,
    body: data
  })

  if (!response.ok) {
    throw Error(response.statusText)
  }
  try {
    const parsedResponse = await response.json()
    return {
      data: parsedResponse
    }
  } catch (e) {
    return {
      data: undefined
    }
  }
}

export { post }
