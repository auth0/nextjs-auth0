export abstract class SdkError extends Error {
  public abstract code: string;
}

/**
 * Represents an error related to the SDK configuration.
 */
export class ConfigurationError extends SdkError {
  public code: string = "configuration_error";

  constructor(message?: string) {
    super(message ?? "The configuration is invalid.");
    this.name = "ConfigurationError";
  }
}
