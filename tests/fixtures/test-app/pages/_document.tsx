import React from 'react';
import Document from 'next/document';

// TODO: Stubbing out the document to resolve "Invalid hook call"
class MyDocument extends Document {
  static getInitialProps(ctx): any {
    return Document.getInitialProps(ctx);
  }

  render(): any {
    return <div>Blank Document</div>;
  }
}

export default MyDocument;
