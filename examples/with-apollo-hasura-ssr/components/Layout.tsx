import Head from 'next/head'
import { ReactNode } from 'react'
import Header from './Header'

type Props = Readonly<{
  loading?: boolean;
  children: ReactNode;
}>

const Layout = ({ children }: Props) => (
  <div id='layout'>
    <Head>
      <title>Next.js with Auth0</title>
    </Head>

    <Header />

    <main>
      <div className="container">{children}</div>
    </main>

    <style jsx>{`
      .container {
        max-width: 42rem;
        margin: 1.5rem auto;
      }
    `}</style>
    <style jsx global>{`
      body {
        margin: 0;
        color: #333;
        font-family: -apple-system, 'Segoe UI';
      }
    `}</style>
  </div>
)

export default Layout
