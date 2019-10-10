

async function post(url, body, fetchMethod = null) {
  console.log(url, body)
  const fetch = typeof window !== 'undefined' && window.fetch != null ? window.fetch : await import('node-fetch')
  const data = JSON.stringify(body);
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }


  const response = await fetch(url, {
    method: 'POST',
    headers: headers,
    body: data
  })
  console.log(response)

  if (!response.ok) {
    throw Error(response.statusText)
  }
  try {
    const parsedResponse = await response.json()
    console.log(parsedResponse)
    return {
      'data': parsedResponse
    }
  }
  catch (e) {
    console.log(e)
    return {
      'data': undefined
    }
  }
}

export { post }