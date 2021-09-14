import React from 'react';
import Document, { DocumentContext, DocumentInitialProps } from 'next/document';

class MyDocument extends Document {
  static getInitialProps(ctx: DocumentContext): Promise<DocumentInitialProps> {
    return Document.getInitialProps(ctx);
  }

  render(): React.ReactElement {
    return <div>Blank Document</div>;
  }
}

export default MyDocument;
