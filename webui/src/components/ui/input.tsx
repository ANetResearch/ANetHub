import * as React from "react";
import { cn } from "../../lib/utils";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-10 w-full border border-gray-300 bg-white px-3 text-sm text-black placeholder:text-gray-400",
        "outline-none transition-colors focus:border-[#E60000] focus:ring-2 focus:ring-[#E60000]/15",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      "w-full border border-gray-300 bg-white px-3 py-2 text-sm text-black placeholder:text-gray-400",
      "outline-none transition-colors focus:border-[#E60000] focus:ring-2 focus:ring-[#E60000]/15 resize-none",
      className,
    )}
    {...props}
  />
));
Textarea.displayName = "Textarea";
